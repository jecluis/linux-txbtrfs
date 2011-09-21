/*
 * Copyright (C) 2011 Joao Eduardo Luis.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA.
 */
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include "ctree.h"
#include "transaction.h"
#include "disk-io.h"
#include "btrfs_inode.h"
#include "txbtrfs.h"
#include "txbtrfs-log.h"
#include "compat.h"
#include "tree-log.h"


#ifdef __TXBTRFS_DEBUG__

static inline void
symexec_print_dbg_file(const char * function, struct btrfs_acid_log_file * file)
{
	if (!function || !file) {
		printk(KERN_DEBUG "<SYM-EXEC> Missing parameters\n");
		return;
	}

	printk(KERN_DEBUG "<SYM-EXEC> (%s): parent: %llu, ino: %llu, name: %.*s\n",
			function,
			file->parent_location.objectid, file->location.objectid,
			file->name.len, file->name.name);
}

#define BTRFS_SYM_DBG(fmt, args...) \
	printk(KERN_DEBUG "<SYM-EXEC> (%s): " fmt, __FUNCTION__, ## args)
#define BTRFS_SYM_PRINT(fmt, args...) \
	printk(KERN_DEBUG "<SYM-EXEC> " fmt, ## args)
#define BTRFS_SYM_DBG_FILE(file_ptr) \
	symexec_print_dbg_file(__FUNCTION__, file_ptr)
#else
#define BTRFS_SYM_DBG(fmt, args...) do {} while (0)
#define BTRFS_SYM_PRINT(fmt, args...) do {} while (0)
#define BTRFS_SYM_DBG_FILE(file_ptr) do {} while (0)
#endif /* __TXBTRFS_DEBUG__ */

/* this may very well be as stupid in the future as it is now, but let give
 * us some room to expand if we need more than a single 'boolean' variable.
 */
#define ORIGIN_LOCAL	1
#define ORIGIN_GLOBAL	2

#define SYMEXEC_CONFLICT 	-EPERM
#define SYMEXEC_OKAY		0

/* symexec tree's lists entry */
struct symexec_entry
{
	struct list_head list;
	u64 ino;
	struct btrfs_acid_log_file * file;
	u8 origin;
	struct btrfs_acid_log_entry * log_entry;

	u8 invalidated;
	struct list_head reconcile_list;
};

/* symexec tree entry for any tree */
struct symexec_tree_entry
{
	struct rb_node rb_node;
	u64 ino;
};

/* symexec tree entry for all trees mapping (inode -> list) */
struct symexec_list_tree_entry
{
	struct rb_node rb_node;
	u64 ino;
	struct list_head list;
};

struct symexec_nlinks_tree_entry
{
	struct rb_node rb_node;
	u64 ino;
	unsigned int nlinks;
};

struct symexec_ino_map_entry
{
	struct rb_node rb_node;
	u64 ino;
	u64 target_ino;
};

/* special Blocks tree entry to mark a truncate and still keep all the written
 * blocks affected by the truncate. May not be the best solution, but is the
 * one we have so far.
 *
 * "inherits" from symexec_entry
 */
struct symexec_blocks_truncate
{
	struct list_head list;
	u64 ino;
	struct btrfs_acid_log_file * file;
	u8 origin;
	struct btrfs_acid_log_entry * log_entry;

	struct list_head truncated_blocks_list;
};

struct symexec_interval_entry
{
	struct rb_node rb_node;
	u64 start; // not pgoff_t to match symexec_tree_entry
	pgoff_t end;
};


/* symexec control data structure */
struct symexec_ctl
{
	struct rb_root dir; 	// ino -> list<symexec_entry>
	struct rb_root rem;		// ino -> list<symexec_entry>
	struct rb_root nlinks;	// ino -> unsigned int
	struct rb_root blocks;	// ino -> list<symexec_entry>
	struct rb_root ino_map; // ino -> ino
	struct rb_root dirty_dirs; // tree of 'ino'

	struct list_head reconcile_log;

	// snapshot to be validated in the end of symexec
	struct btrfs_acid_snapshot * target_snap;
};

static void __symexec_destroy_entry(struct symexec_entry * entry);
static struct symexec_entry *
__symexec_create_entry(u64 ino, struct btrfs_acid_log_file * file,
		struct btrfs_acid_log_entry * log_entry, u8 origin);

/**
 * __tree_insert -- insert into any tree, based on the common header
 * shared by all their entries.
 */
static struct rb_node * __tree_insert(struct rb_root * root, u64 ino,
//		struct symexec_tree_entry * entry)
		struct rb_node * node)
{
	struct rb_node ** p = &root->rb_node;
	struct rb_node * parent = NULL;
	struct symexec_tree_entry * p_entry;

	if (!root || !node)
		return ERR_PTR(-EINVAL);

	while (*p) {
		parent = *p;
		p_entry = rb_entry(parent, struct symexec_tree_entry, rb_node);

//		if (entry->ino < p_entry->ino)
		if (ino < p_entry->ino)
			p = &(*p)->rb_left;
//		else if (entry->ino > p_entry->ino)
		else if (ino > p_entry->ino)
			p = &(*p)->rb_right;
		else
			return parent;
	}

//	rb_link_node(entry->rb_node, parent, p);
//	rb_insert_color(entry->rb_node, root);
	rb_link_node(node, parent, p);
	rb_insert_color(node, root);

	return NULL;
}

/**
 * __tree_search -- search by inode value in any one of the trees.
 */
static struct rb_node * __tree_search(struct rb_root * root, u64 ino)
{
	struct rb_node * node = root->rb_node;
	struct symexec_tree_entry * entry;

	if (!root)
		return ERR_PTR(-EINVAL);

	while (node) {
		entry = rb_entry(node, struct symexec_tree_entry, rb_node);

		if (ino < entry->ino)
			node = node->rb_left;
		else if (ino > entry->ino)
			node = node->rb_right;
		else
			return node;
	}
	return NULL;
}

/**
 * __tree_erase -- remove a node from a tree.
 *
 * NOTE: this approach seems way to simple right now. It may be so, or we may
 * be oversimplifying it. Take care.
 */
static void __tree_erase(struct rb_root * root, struct rb_node * node)
{
	if (!root || !node)
		return;

	if (!RB_EMPTY_NODE(node))
		rb_erase(node, root);
}

static struct list_head * __list_tree_get(struct rb_root * root, u64 ino)
{
	struct list_head * lst;
	struct rb_node * node;
	struct symexec_list_tree_entry * entry;

	if (!root)
		return ERR_PTR(-EINVAL);

	lst = NULL;
	node = __tree_search(root, ino);
	if (node) {
		entry = rb_entry(node, struct symexec_list_tree_entry, rb_node);
		lst = &entry->list;
	}

	return lst;
}

static int __list_tree_put(struct rb_root * root, u64 ino,
		struct symexec_entry * entry)
{
	struct rb_node * node;
	struct list_head * lst;
	struct symexec_list_tree_entry * list_entry;

	if (!root || !entry)
		return -EINVAL;

	lst = __list_tree_get(root, ino);
	if (!lst) {
		list_entry = kzalloc(sizeof(*list_entry), GFP_NOFS);
		if (!list_entry)
			return -ENOMEM;
		list_entry->ino = ino;
		INIT_LIST_HEAD(&list_entry->list);

		node = __tree_insert(root, ino, &list_entry->rb_node);
		BUG_ON(node != NULL);

		lst = &list_entry->list;
	}
	list_add_tail(&entry->list, lst);

#if 0
	list_entry = __list_tree_get(root, ino);
	if (!list_entry) {
		list_entry = kzalloc(sizeof(*list_entry), GFP_NOFS);
		if (!list_entry)
			return -ENOMEM;
		list_entry->ino = ino;

		node = __tree_insert(root, ino, &list_entry->rb_node);
		BUG_ON(node != NULL);
	}
	list_add_tail(&entry->list, list_entry);
#endif

	return 0;
}

/**
 * __list_tree_lookup_file - Looks up a file @name in a given @parent.
 *
 * If @ino is 0, then the method should ignore this parameter and, instead,
 * lookup any file with the same @name, within the same @parent, despite its
 * inode number.
 */
static struct symexec_entry *
__list_tree_lookup_file(struct rb_root * root, u64 key, u64 ino,
		struct qstr * name)
{
	struct list_head * lst;
	struct symexec_entry * entry;
	int found = 0;

	if (!root || !name)
		return ERR_PTR(-EINVAL);

	lst = __list_tree_get(root, key);
	if (IS_ERR(lst))
		return ERR_CAST(lst);
	else if (!lst) {
		return NULL;
	}

	if (list_empty(lst))
		return NULL;

	list_for_each_entry(entry, lst, list) {
		if (((ino != 0) && (entry->ino != ino))
				|| (entry->file->name.hash != name->hash)
				|| (entry->file->name.len != name->len)) {
			BTRFS_SYM_PRINT("k: %llu, i: %llu, %.*s (h: %u) "
					"!= k: %llu, i: %llu, n: %.*s (h: %u)\n",
					key, ino, name->len, name->name, name->hash,
					key, entry->ino, entry->file->name.len,
					entry->file->name.name, entry->file->name.hash);
			continue;
		}

		if (!memcmp(entry->file->name.name, name->name, name->len)) {
			found = 1;
			break;
		}
	}

	if (!found) {
		BTRFS_SYM_DBG("Unable to find ino %llu '%.*s' in key %llu\n",
				ino, name->len, name->name, key);
		return NULL;
	}

	return entry;
}

/**
 * symexec_ -- put something into an inode map.
 * @returns: 0 if successful; < 0 otherwise.
 */
static int symexec_ino_map_put(struct symexec_ctl * symexec, u64 key, u64 val)
{
	struct symexec_ino_map_entry * entry;
	struct rb_node * n;

	if (!symexec)
		return -EINVAL;

	entry = kzalloc(sizeof(*entry), GFP_NOFS);
	if (!entry)
		return -ENOMEM;

	entry->ino = key;
	entry->target_ino = val;

	n = __tree_insert(&symexec->ino_map, key, &entry->rb_node);
	if (IS_ERR(n)) {
		kfree(entry);
		return PTR_ERR(n);
	}
	return 0;
}

/**
 * symexec_ino_map_get -- get something from an inode map.
 * @returns: < 0 or error; 0 otherwise. If not found, val == 0.
 */
//static int __ino_map_get(struct rb_root * root, u64 key, u64 * value)
static int symexec_ino_map_get(struct symexec_ctl * symexec, u64 key, u64 * val)
{
	struct rb_node * node;
	struct symexec_ino_map_entry * entry;

	if (!symexec || !val)
		return -EINVAL;

	*val = 0;

	node = __tree_search(&symexec->ino_map, key);
	if (IS_ERR_OR_NULL(node)) {
		return (IS_ERR(node) ? PTR_ERR(node) : 0);
	}

	entry = rb_entry(node, struct symexec_ino_map_entry, rb_node);
	*val = entry->target_ino;

	return 0;
}

/**
 * __symexec_get_mapped -- get a correct inode for an operation.
 *
 * This method performs a very specific task, which undocumented may leave
 * the reader both bewildered and thinking what an idiot we could possibly be.
 *
 * Well, the idea is simple. Sometimes we need to check if there is a mapping
 * for an inode. If such mapping exists, we need its value. However, if no
 * mapping exists, we consider that the inode is well mapped (or not requiring
 * said mapping) and we want the value passed as @key.
 *
 * This is what is done here, since this code is used far too many times for
 * our own taste, and having it spread around most methods is quite ugly imo.
 *
 * The method will return < 0 on error, zero if no mapping was found or one if
 * the value was successfully mapped to an existing value.
 */
static int __symexec_get_mapped(struct symexec_ctl * symexec,
		u64 key, u64 * val)
{
	int err;
	if (!symexec || !val)
		return -EINVAL;

	err = symexec_ino_map_get(symexec, key, val);
	if (err < 0)
		return err;

	if (!*val)
		*val = key;
	else
		return 1;

	return 0;
}

static int
symexec_nlinks_put(struct symexec_ctl * symexec, u64 key, unsigned int val)
{
	struct symexec_nlinks_tree_entry * entry;
	struct rb_node * n;

	if (!symexec)
		return -EINVAL;

	entry = kzalloc(sizeof(*entry), GFP_NOFS);
	if (!entry)
		return -ENOMEM;

	entry->ino = key;
	entry->nlinks = val;

	n = __tree_insert(&symexec->nlinks, key, &entry->rb_node);
	if (IS_ERR(n)) {
		kfree(entry);
		return PTR_ERR(n);
	}
	return 0;
}

static struct symexec_nlinks_tree_entry *
symexec_nlinks_get_entry(struct symexec_ctl * symexec, u64 key)
{
	struct rb_node * node;
	struct symexec_nlinks_tree_entry * entry;

	if (!symexec)
		return ERR_PTR(-EINVAL);

	node = __tree_search(&symexec->nlinks, key);
	if (IS_ERR(node))
		return ERR_CAST(node);
	if (!node)
		return NULL;

	entry = rb_entry(node, struct symexec_nlinks_tree_entry, rb_node);
	return entry;
}

static int
symexec_nlinks_get(struct symexec_ctl * symexec, u64 key, unsigned int * val)
{
	struct symexec_nlinks_tree_entry * entry;

	if (!symexec || !val)
		return -EINVAL;
	*val = 0;

#if 0

	node = __tree_search(&symexec->nlinks, key);
	if (IS_ERR_OR_NULL(node)) {
		return (IS_ERR(node) ? PTR_ERR(node) : -ENOENT);
	}

	entry = rb_entry(node, struct symexec_nlinks_tree_entry, rb_node);
#endif

	entry = symexec_nlinks_get_entry(symexec, key);
	if (IS_ERR(entry))
		return PTR_ERR(entry);

	if (entry)
		*val = entry->nlinks;

	return 0;
}

static int symexec_nlinks_contains(struct symexec_ctl * symexec, u64 key)
{
	if (!symexec)
		return -EINVAL;
	return (symexec_nlinks_get_entry(symexec, key) != NULL);
}

static int symexec_nlinks_inc(struct symexec_ctl * symexec, u64 key)
{
	struct symexec_nlinks_tree_entry * entry;

	if (!symexec)
		return -EINVAL;

#if 0
	node = __tree_search(&symexec->nlinks, key);
	if (IS_ERR(node))
		return PTR_ERR(node);
	if (!node)
		return symexec_nlinks_put(symexec, key, 1);

	entry = rb_entry(node, struct symexec_nlinks_tree_entry, rb_node);
#endif

	entry = symexec_nlinks_get_entry(symexec, key);
	if (IS_ERR(entry))
		return PTR_ERR(entry);
	if (!entry)
		return symexec_nlinks_put(symexec, key, 1);

	entry->nlinks ++;

	return 0;
}

static int symexec_nlinks_dec_return(struct symexec_ctl * symexec, u64 key)
{
	struct symexec_nlinks_tree_entry * entry;

	if (!symexec)
		return -EINVAL;

	entry = symexec_nlinks_get_entry(symexec, key);
	if (IS_ERR(entry))
		return PTR_ERR(entry);
	if (!entry)
		return -ENOENT;

	entry->nlinks --;
	WARN_ON(entry->nlinks < 0);

	return entry->nlinks;
}

static int symexec_nlinks_dec(struct symexec_ctl * symexec, u64 key)
{
	struct symexec_nlinks_tree_entry * entry;

	if (!symexec)
		return -EINVAL;

#if 0
	node = __tree_search(&symexec->nlinks, key);
	if (IS_ERR(node))
		return PTR_ERR(node);
	if (!node)
		return symexec_nlinks_put(symexec, key, 1);

	entry = rb_entry(node, struct symexec_nlinks_tree_entry, rb_node);
#endif

	entry = symexec_nlinks_get_entry(symexec, key);
	if (IS_ERR(entry))
		return PTR_ERR(entry);
	if (!entry)
		return -ENOENT;

	entry->nlinks --;
	WARN_ON(entry->nlinks < 0);

	return 0;
}

static int symexec_dir_put(struct symexec_ctl * symexec, u64 key,
		struct symexec_entry * entry)
{
	if (!symexec || !entry)
		return -EINVAL;

	return __list_tree_put(&symexec->dir, key, entry);
}

/**
 * symexec_dir_lookup_file - Looks up a file in the dir tree.
 *
 * This method is just a wrapper for __list_tree_lookup_file, just so we
 * don't have to specify the tree we want to access when we clearly want the
 * dir tree.
 */
static struct symexec_entry *
symexec_dir_lookup_file(struct symexec_ctl * symexec, u64 parent, u64 ino,
		struct qstr * name)
{
	if (!symexec || !name)
		return ERR_PTR(-EINVAL);
	return __list_tree_lookup_file(&symexec->dir, parent, ino, name);
}

static int symexec_dir_remove(struct symexec_ctl * symexec, u64 parent,
		u64 ino, struct qstr * name)
{
#if 0
	struct list_head * lst;
	struct symexec_entry * entry;
	int found = 0;

	if (!symexec || !name)
		return -EINVAL;

	lst = __list_tree_get(&symexec->dir, parent);
	if (IS_ERR(lst))
		return PTR_ERR(lst);
	else if (!lst)
		return -ENOENT;

	if (list_empty(lst))
		return -ENOENT;

	list_for_each_entry(entry, lst, list) {
		if ((entry->ino != ino) || (entry->file->name.hash != name->hash)
				|| (entry->file->name.len != name->len))
			continue;

		if (!memcmp(entry->file->name.name, name->name, name->len)) {
			found = 1;
			break;
		}
	}

	if (!found) {
		BTRFS_SYM_DBG("Unable to find ino %llu '%.*s' in parent %llu\n",
				ino, name->len, name->name, parent);
		return -ENOENT;
	}
#endif

	struct symexec_entry * entry;

	if (!symexec || !name)
		return -EINVAL;

	entry = symexec_dir_lookup_file(symexec, parent, ino, name);
	if (IS_ERR(entry))
		return PTR_ERR(entry);
	if (!entry)
		return -ENOENT;

	list_del(&entry->list);
	__symexec_destroy_entry(entry);

	return 0;
}

/**
 * symexec_dir_match_file - Checks if any file in the symbolic execution tree
 * matches @file.
 *
 * @return: 0 if no match was found, 1 if a match was found, or < 0 on error.
 */
static int symexec_dir_match_file(struct symexec_ctl * symexec,
		u64 parent, u64 ino, struct qstr * name, u8 * origin)
{
	struct symexec_entry * entry;

	if (!symexec || !name)
		return -EINVAL;

	entry = symexec_dir_lookup_file(symexec, parent, ino, name);
	if (IS_ERR(entry)) {
		BTRFS_SYM_DBG("DIR-FIND-FILE > parent: %llu, ino: %llu, name: %.*s\n",
				parent, ino, name->len, name->name);
		return PTR_ERR(entry);
	} else if (entry) {
		if (origin)
			*origin = entry->origin;
		if (entry->invalidated)
			return 0;
		return 1;
	}

	return 0;
}

static int symexec_rem_put(struct symexec_ctl * symexec, u64 key,
		struct symexec_entry * entry)
{
	if (!symexec || !entry)
		return -EINVAL;
	return __list_tree_put(&symexec->rem, key, entry);
}

static struct list_head * symexec_rem_get(struct symexec_ctl * symexec, u64 ino)
{
	if (!symexec)
		return ERR_PTR(-EINVAL);

	return __list_tree_get(&symexec->rem, ino);
}

static struct symexec_entry *
symexec_rem_lookup_file(struct symexec_ctl * symexec, u64 key, u64 ino,
		struct qstr * name)
{
	if (!symexec || !name)
		return ERR_PTR(-EINVAL);
	return __list_tree_lookup_file(&symexec->rem, key, ino, name);
}

static int symexec_rem_match_file(struct symexec_ctl * symexec, u64 key,
		u64 ino, struct qstr * name, u8 * origin)
{
	struct symexec_entry * entry;

	if (!symexec || !name)
		return -EINVAL;

	entry = symexec_rem_lookup_file(symexec, key, ino, name);
	if (IS_ERR(entry)) {
		BTRFS_SYM_DBG("REM-LOOKUP-FILE > parent: %llu, ino: %llu, name: %.*s\n",
				key, ino, name->len, name->name);
		return PTR_ERR(entry);
	} else if (entry) {
		if (origin)
			*origin = entry->origin;
		return 1;
	}
	return 0;
}


static int symexec_blocks_put(struct symexec_ctl * symexec, u64 ino,
		struct btrfs_acid_log_rw * entry, u8 origin)
{
	struct symexec_entry * sym_entry;

	if (!symexec || !entry)
		return -EINVAL;

	sym_entry = __symexec_create_entry(ino, &entry->file,
			(void *) entry, origin);
	if (IS_ERR(sym_entry))
		return PTR_ERR(sym_entry);

	return __list_tree_put(&symexec->blocks, ino, sym_entry);
}

static struct list_head *
symexec_blocks_get(struct symexec_ctl * symexec, u64 ino)
{
	if (!symexec)
		return ERR_PTR(-EINVAL);

	return __list_tree_get(&symexec->blocks, ino);
}

/**
 * symexec_dirty_dir_put - Adds an inode value to the dirty dir tree.
 *
 * An entry in this tree means that some creation or removal operation was
 * made on the directory with inode value @ino.
 */
static int symexec_dirty_dir_put(struct symexec_ctl * symexec, u64 ino)
{
	struct symexec_tree_entry * entry;
	struct rb_node * n;

	if (!symexec)
		return -EINVAL;

	n = __tree_search(&symexec->dirty_dirs, ino);
	if (IS_ERR(n))
		return PTR_ERR(n);
	else if (n != NULL) {
		/* entry exists; nothing to do here. */
		goto out;
	}

	entry = kzalloc(sizeof(*entry), GFP_NOFS);
	if (!entry)
		return -ENOMEM;

	entry->ino = ino;
	n = __tree_insert(&symexec->dirty_dirs, ino, &entry->rb_node);
	if (IS_ERR(n)) {
		kfree(entry);
		return PTR_ERR(n);
	}
out:
	return 0;
}

static int symexec_dirty_dir_contains(struct symexec_ctl * symexec, u64 ino)
{
	struct rb_node * n;

	if (!symexec)
		return -EINVAL;

	n = __tree_search(&symexec->dirty_dirs, ino);
	if (IS_ERR(n))
		return PTR_ERR(n);
	else if (!n)
		return 0;

	return 1;
}

static int symexec_reconcile_log_put(struct symexec_ctl * symexec,
		u64 ino, struct btrfs_acid_log_file * file,
		struct btrfs_acid_log_entry * entry)
{
	struct symexec_entry * sym_entry;

	if (!symexec || !file || !entry)
		return -EINVAL;

	sym_entry = __symexec_create_entry(ino, file, entry, ORIGIN_GLOBAL);
	if (IS_ERR(sym_entry))
		return PTR_ERR(sym_entry);

	list_add_tail(&sym_entry->reconcile_list, &symexec->reconcile_log);

	return 0;
}

/**
 * symexec_create -- creates & initializes a symbolic execution.
 */
static struct symexec_ctl * symexec_create(struct btrfs_acid_snapshot * snap)
{
	struct symexec_ctl * symexec;

	if (!snap || !snap->root)
		return ERR_PTR(-EINVAL);

	symexec = kzalloc(sizeof(*symexec), GFP_NOFS);
	if (!symexec)
		return ERR_PTR(-ENOMEM);

	symexec->dir = RB_ROOT;
	symexec->rem = RB_ROOT;
	symexec->nlinks = RB_ROOT;
	symexec->blocks = RB_ROOT;
	symexec->ino_map = RB_ROOT;
	symexec->dirty_dirs = RB_ROOT;

	INIT_LIST_HEAD(&symexec->reconcile_log);

	symexec->target_snap = snap;

	return symexec;
}

static void __symexec_destroy_tree_nlinks(struct symexec_ctl * symexec)
{
	struct rb_node * node, * next_node;
	struct symexec_nlinks_tree_entry * entry;

	for (node = rb_first(&symexec->nlinks); node; ) {
		next_node = rb_next(node);
		entry = rb_entry(node, struct symexec_nlinks_tree_entry, rb_node);
		rb_erase(node, &symexec->nlinks);
		kfree(entry);
		node = next_node;
	}
}

static void __symexec_destroy_tree_ino(struct symexec_ctl * symexec)
{
	struct rb_node * node, * next_node;
	struct symexec_ino_map_entry * entry;

	for (node = rb_first(&symexec->ino_map); node; ) {
		next_node = rb_next(node);
		entry = rb_entry(node, struct symexec_ino_map_entry, rb_node);
		rb_erase(node, &symexec->ino_map);
		kfree(entry);
		node = next_node;
	}
}

static void __symexec_destroy_tree_dirty_dirs(struct symexec_ctl * symexec)
{
	struct rb_node * node, * next_node;
	struct symexec_tree_entry * entry;

	for (node = rb_first(&symexec->dirty_dirs); node; ) {
		next_node = rb_next(node);
		entry = rb_entry(node, struct symexec_tree_entry, rb_node);
		rb_erase(node, &symexec->nlinks);
		kfree(entry);
		node = next_node;
	}
}

static void __symexec_destroy_list(struct list_head * list)
{
	struct symexec_entry * entry;
	struct list_head * lst, * ptr;

	list_for_each_safe(lst, ptr, list) {
		entry = list_entry(lst, struct symexec_entry, list);
		list_del(lst);
		kfree(entry);
	}
}

static void __symexec_destroy_list_tree(struct rb_root * root)
{
	struct rb_node * node, * next_node;
	struct symexec_list_tree_entry * list_entry;

	for (node = rb_first(root); node; ) {
		next_node = rb_next(node);
		list_entry = rb_entry(node, struct symexec_list_tree_entry, rb_node);
		rb_erase(node, root);

		__symexec_destroy_list(&list_entry->list);

		kfree(list_entry);
		node = next_node;
	}
}

static void symexec_destroy(struct symexec_ctl * symexec)
{
	if (!symexec)
		return;

	__symexec_destroy_tree_nlinks(symexec);
	__symexec_destroy_tree_ino(symexec);
	__symexec_destroy_tree_dirty_dirs(symexec);

	__symexec_destroy_list_tree(&symexec->blocks);
	__symexec_destroy_list_tree(&symexec->dir);
	__symexec_destroy_list_tree(&symexec->rem);

	__symexec_destroy_list(&symexec->reconcile_log);
}

static void __print_dir_list(struct symexec_ctl * symexec,
		struct list_head * lst)
{
	struct symexec_entry * entry;
	u64 parent, ino;
	unsigned int nlink = 31337; /* this is just a control value */
	int err;

	WARN_ON(!lst);
	if (!lst)
		return;

	list_for_each_entry(entry, lst, list) {
		parent = entry->file->parent_location.objectid;
		ino = entry->file->location.objectid;

		err = __symexec_get_mapped(symexec, parent, &parent);
		if (err < 0) {
			BTRFS_SYM_PRINT("ERROR acquiring parent map for %llu", entry->ino);
		}

		err = __symexec_get_mapped(symexec, ino, &ino);
		if (err < 0) {
			BTRFS_SYM_PRINT("ERROR acquiring map for %llu", entry->ino);
		}

		err = symexec_nlinks_get(symexec, ino, &nlink);
		if (err < 0) {
			BTRFS_SYM_PRINT("ERROR acquiring nlink for %llu", ino);
		}
		BTRFS_SYM_PRINT("\t%sparent: %llu, ino: %llu, name: %.*s, nlink: %u, "
				"type: %s\n",
				(entry->invalidated ? "(INVALID) " : ""),
				parent, ino,
				entry->file->name.len, entry->file->name.name, nlink,
				btrfs_acid_log_type_to_str(entry->log_entry->type));
	}
}

static void __print_blocks_list(struct symexec_ctl * symexec,
		struct list_head * lst)
{
	struct symexec_entry * entry;
	struct symexec_blocks_truncate * trunc;
	u64 parent, ino;
	unsigned int nlink = 31337; /* this is just a control value */
	int err;

	WARN_ON(!lst);
	if (!lst)
		return;

	list_for_each_entry(entry, lst, list) {
		parent = entry->file->parent_location.objectid;
		ino = entry->file->location.objectid;

		err = __symexec_get_mapped(symexec, parent, &parent);
		if (err < 0) {
			BTRFS_SYM_PRINT("ERROR acquiring parent map for %llu", entry->ino);
		}

		err = __symexec_get_mapped(symexec, ino, &ino);
		if (err < 0) {
			BTRFS_SYM_PRINT("ERROR acquiring map for %llu", entry->ino);
		}

		err = symexec_nlinks_get(symexec, ino, &nlink);
		if (err < 0) {
			BTRFS_SYM_PRINT("ERROR acquiring nlink for %llu", ino);
		}

		BTRFS_SYM_PRINT("\tparent: %llu, ino: %llu, name: %.*s, nlink: %u"
				", type: %s\n",
				parent, ino,
				entry->file->name.len, entry->file->name.name, nlink,
				btrfs_acid_log_type_to_str(entry->log_entry->type));

		if (entry->log_entry->type == BTRFS_ACID_LOG_TRUNCATE) {
			trunc = (struct symexec_blocks_truncate *) entry;
			if (list_empty(&trunc->truncated_blocks_list)) {
				BTRFS_SYM_PRINT("\tNo blocks truncated\n");
				continue;
			}
			BTRFS_SYM_PRINT("\tTruncated:\n");
			__print_dir_list(symexec, &trunc->truncated_blocks_list);
		}
	}
}

static void symexec_print_dir_tree(struct symexec_ctl * symexec)
{
	struct rb_node * node;
	struct symexec_list_tree_entry * entry;

	WARN_ON(!symexec);
	if (!symexec)
		return;

	BTRFS_SYM_PRINT("----------------------------------------------\n");
	BTRFS_SYM_PRINT("  DIR tree (%d)\n", symexec->target_snap->owner_pid);

	for (node = rb_first(&symexec->dir); node; node = rb_next(node)) {
		entry = rb_entry(node, struct symexec_list_tree_entry, rb_node);
		BTRFS_SYM_PRINT("ino: %llu\n", entry->ino);
		__print_dir_list(symexec, &entry->list);
	}
	BTRFS_SYM_PRINT("----------------------------------------------\n");
}

static void symexec_print_rem_tree(struct symexec_ctl * symexec)
{
	struct rb_node * node;
	struct symexec_list_tree_entry * entry;

	WARN_ON(!symexec);
	if (!symexec)
		return;

	BTRFS_SYM_PRINT("----------------------------------------------\n");
	BTRFS_SYM_PRINT("  REM tree (%d)\n", symexec->target_snap->owner_pid);

	for (node = rb_first(&symexec->rem); node; node = rb_next(node)) {
		entry = rb_entry(node, struct symexec_list_tree_entry, rb_node);
		BTRFS_SYM_PRINT("ino: %llu\n", entry->ino);
		__print_dir_list(symexec, &entry->list);
	}
	BTRFS_SYM_PRINT("----------------------------------------------\n");
}

static void symexec_print_blocks_tree(struct symexec_ctl * symexec)
{
	struct rb_node * node;
	struct symexec_list_tree_entry * entry;

	WARN_ON(!symexec);
	if (!symexec)
		return;

	BTRFS_SYM_PRINT("----------------------------------------------\n");
	BTRFS_SYM_PRINT("  BLOCKS tree (%d)\n", symexec->target_snap->owner_pid);

	for (node = rb_first(&symexec->blocks); node; node = rb_next(node)) {
		entry = rb_entry(node, struct symexec_list_tree_entry, rb_node);
		BTRFS_SYM_PRINT("ino: %llu\n", entry->ino);
		__print_blocks_list(symexec, &entry->list);
	}
	BTRFS_SYM_PRINT("----------------------------------------------\n");
}

static void symexec_print_dirty_dirs_tree(struct symexec_ctl * symexec)
{
	struct rb_node * node;
	struct symexec_tree_entry * entry;

	WARN_ON(!symexec);
	if (!symexec)
		return;

	BTRFS_SYM_PRINT("----------------------------------------------\n");
	BTRFS_SYM_PRINT("  Dirty Dirs Tree (%d)\n",
			symexec->target_snap->owner_pid);

	for (node = rb_first(&symexec->dirty_dirs); node; node = rb_next(node)) {
		entry = rb_entry(node, struct symexec_tree_entry, rb_node);
		BTRFS_SYM_PRINT("ino: %llu\n", entry->ino);
	}
	BTRFS_SYM_PRINT("----------------------------------------------\n");
}

static void symexec_print_reconcile_log(struct symexec_ctl * symexec)
{
	struct symexec_entry * entry;
	u64 parent, ino;
	unsigned int nlink = 31337; /* this is just a control value */
	int err;

	WARN_ON(!symexec);
	if (!symexec)
		return;

	BTRFS_SYM_PRINT("----------------------------------------------\n");
	BTRFS_SYM_PRINT("  Reconcile Log (%d)\n",
			symexec->target_snap->owner_pid);
	list_for_each_entry(entry, &symexec->reconcile_log, reconcile_list) {
		parent = entry->file->parent_location.objectid;
		ino = entry->file->location.objectid;

		err = __symexec_get_mapped(symexec, parent, &parent);
		if (err < 0) {
			BTRFS_SYM_PRINT("ERROR acquiring parent map for %llu", entry->ino);
		}

		err = __symexec_get_mapped(symexec, ino, &ino);
		if (err < 0) {
			BTRFS_SYM_PRINT("ERROR acquiring map for %llu", entry->ino);
		}

		err = symexec_nlinks_get(symexec, ino, &nlink);
		if (err < 0) {
			BTRFS_SYM_PRINT("ERROR acquiring nlink for %llu", ino);
		}
		BTRFS_SYM_PRINT("\t%sparent: %llu, ino: %llu, name: %.*s, nlink: %u, "
				"type: %s\n",
				(entry->invalidated ? "(INVALID) " : ""),
				parent, ino,
				entry->file->name.len, entry->file->name.name, nlink,
				btrfs_acid_log_type_to_str(entry->log_entry->type));
	}
	BTRFS_SYM_PRINT("----------------------------------------------\n");
}

static void __symexec_destroy_entry(struct symexec_entry * entry);

static int __symexec_fill_entry(struct symexec_entry * entry, u64 ino,
		struct btrfs_acid_log_file * file,
		struct btrfs_acid_log_entry * log_entry, u8 origin)
{
	if (!entry || !file || !log_entry)
		return -EINVAL;

	entry->ino = ino;
	entry->file = file;
	entry->log_entry = log_entry;
	entry->origin = origin;
	return 0;
}

static struct symexec_entry *
__symexec_create_entry(u64 ino, struct btrfs_acid_log_file * file,
		struct btrfs_acid_log_entry * log_entry, u8 origin)
{
	struct symexec_entry * entry;
	int err;

	if (!file || !log_entry)
		return ERR_PTR(-EINVAL);

	entry = kzalloc(sizeof(*entry), GFP_NOFS);
	if (!entry)
		return ERR_PTR(-ENOMEM);
#if 0
	entry->ino = ino;
	entry->file = file;
	entry->log_entry = log_entry;
	entry->origin = origin;
#endif

	err = __symexec_fill_entry(entry, ino, file, log_entry, origin);
	if (err < 0) {
		kfree(entry);
		return ERR_PTR(err);
	}

	return entry;
}

static void __symexec_destroy_entry(struct symexec_entry * entry)
{
	if (entry) {
		kfree(entry);
	}
}

static int __symexec_apply_create(struct symexec_ctl * symexec,
		struct btrfs_acid_log_create * entry)
{
	int err;
	u64 objectid, parent;
	struct symexec_entry * symexec_entry;

	if (!symexec || !entry
			|| ((entry->type != BTRFS_ACID_LOG_CREATE)
					&& (entry->type != BTRFS_ACID_LOG_MKDIR)
					&& (entry->type != BTRFS_ACID_LOG_SYMLINK)
					&& (entry->type != BTRFS_ACID_LOG_MKNOD)))
		return -EINVAL;

	/* look for the entry's parent inode in the inode map */
#if 0
	entry_parent_ino = entry->file.parent_location.objectid;
	err = symexec_ino_map_get(symexec, entry_parent_ino, &parent_ino);
	if (err < 0) {
		BTRFS_SYM_DBG("parent ino: %llu; entry parent ino: %llu\n",
				parent_ino, entry_parent_ino);
		return -EINVAL;
	}

	if (!parent_ino)
		parent_ino = entry_parent_ino;
#endif

	err = __symexec_get_mapped(symexec, entry->file.parent_location.objectid,
			&parent);
	if (err < 0) {
		BTRFS_SYM_DBG("parent ino: %llu; entry parent ino: %llu\n",
				parent, entry->file.parent_location.objectid);
		return err;
	}

	err = btrfs_find_free_objectid(NULL, symexec->target_snap->root,
			parent, &objectid);
	if (err) {
		BTRFS_SYM_DBG("objid: %llu; parent ino: %llu; entry parent ino: %llu\n",
				objectid, parent, entry->file.parent_location.objectid);
		return err;
	}

	err = symexec_reconcile_log_put(symexec, objectid,
			&entry->file, (void *) entry);
	if (err < 0) {
		BTRFS_SYM_DBG("LOG-PUT > Error\n");
		return err;
	}

	symexec_entry = __symexec_create_entry(objectid, &entry->file,
			(void *) entry, ORIGIN_GLOBAL);
	if (IS_ERR(symexec_entry))
		return PTR_ERR(symexec_entry);

//	list_add_tail(&symexec_entry->reconcile_list, &symexec->reconcile_log);


	err = symexec_dir_put(symexec, parent, symexec_entry);
	if (err < 0) {
		BTRFS_SYM_DBG("DIR-PUT > parent: %llu; ino: %llu; file: %*.s\n",
				parent, objectid,
				entry->file.name.len, entry->file.name.name);
		return err;
	}

	err = symexec_ino_map_put(symexec, entry->ino, objectid);
	if (err < 0) {
		BTRFS_SYM_DBG("INO-MAP-PUT > objid: %llu; ino: %llu\n",
				objectid, entry->ino);
		return err;
	}

	err = symexec_nlinks_put(symexec, objectid, 1);
	if (err < 0) {
		BTRFS_SYM_DBG("NLINKS-PUT > objid: %llu; ino: %llu\n",
				objectid, entry->ino);
		return err;
	}

	err = symexec_dirty_dir_put(symexec, parent);
	if (err < 0) {
		BTRFS_SYM_DBG("DIRTY-PUT > parent: %llu\n", parent);
		return err;
	}


	return 0;
}

static int __symexec_apply_unlink_do(struct symexec_ctl * symexec,
		struct btrfs_acid_log_file * file, unsigned int nlink,
		struct btrfs_acid_log_entry * entry)
{
	int err;
	u64 parent;
	u64 ino;
	struct symexec_entry * rem_entry;
	struct symexec_entry * dir_entry;

	if (!symexec || !file || !entry)
		return -EINVAL;

	err = __symexec_get_mapped(symexec, file->parent_location.objectid,
			&parent);
	if (err < 0) {
		BTRFS_SYM_DBG("parent ino: %llu; entry parent ino: %llu\n",
				parent, file->parent_location.objectid);
		return err;
	}

	err = __symexec_get_mapped(symexec, file->location.objectid, &ino);
	if (err < 0) {
		BTRFS_SYM_DBG("parent ino: %llu; ino: %llu\n",
				parent, ino);
		return err;
	}

	/* there is a valid mapping for ino */
	if (err) {
#if 1
		err = symexec_nlinks_dec_return(symexec, ino);
		if (err < 0) {
			BTRFS_SYM_DBG("NLINKS-DEC > parent: %llu; ino: %llu; name: %.*s\n",
					parent, ino, file->name.len, file->name.name);
			return err;
		} else if (!err) {
			err = symexec_dir_remove(symexec, parent, ino, &file->name);
			if (err < 0) {
				BTRFS_SYM_DBG("DIR-REMOVE > parent: %llu; ino: %llu; name: %.*s\n",
						parent, ino, file->name.len, file->name.name);
				return err;
			}
		} else {
			dir_entry = symexec_dir_lookup_file(symexec, parent, ino,
					&file->name);
			if (IS_ERR(dir_entry)) {
				BTRFS_SYM_DBG("DIR-LOOKUP > parent: %llu, ino: %llu, name: %.*s\n",
						parent, ino, file->name.len, file->name.name);
				return PTR_ERR(dir_entry);
			}
			dir_entry->invalidated = 1;
		}
#else
		err = symexec_dir_remove(symexec, parent, ino, &file->name);
		if (err < 0) {
			BTRFS_SYM_DBG("DIR-REMOVE > parent: %llu; ino: %llu; name: %.*s\n",
					parent, ino, file->name.len, file->name.name);
			return err;
		}

		err = symexec_nlinks_dec(symexec, ino);
		if (err < 0) {
			BTRFS_SYM_DBG("NLINKS-DEC > parent: %llu; ino: %llu; name: %.*s\n",
					parent, ino, file->name.len, file->name.name);
			return err;
		}

#endif
	} else {
		rem_entry = __symexec_create_entry(parent, file,
				entry, ORIGIN_GLOBAL);
		if (IS_ERR(rem_entry)) {
			BTRFS_SYM_DBG("CREATE-ENTRY > parent: %llu; ino: %llu; name: %.*s\n",
					parent, ino, file->name.len, file->name.name);
			return PTR_ERR(rem_entry);
		}
		err = symexec_rem_put(symexec, ino, rem_entry);
		if (err < 0) {
			BTRFS_SYM_DBG("REM-PUT > parent: %llu; ino: %llu; name: %.*s\n",
					parent, ino, file->name.len, file->name.name);
			return err;
		}

		err = symexec_nlinks_put(symexec, ino, nlink);
		if (err < 0) {
			BTRFS_SYM_DBG("NLINKS-PUT > parent: %llu; ino: %llu; name: %.*s\n",
					parent, ino, file->name.len, file->name.name);
			return err;
		}
	}

	err = symexec_dirty_dir_put(symexec, parent);
	if (err < 0) {
		BTRFS_SYM_DBG("DIRTY-PUT > parent: %llu\n", parent);
		return err;
	}

	if (entry->type == BTRFS_ACID_LOG_RENAME)
		goto out;

	/*
	reconcile_entry = __symexec_create_entry(ino, file, entry, ORIGIN_GLOBAL);
	if (IS_ERR(reconcile_entry)) {
		BTRFS_SYM_DBG("CREATE-REC-ENTRY > ino: %llu, name: %.*s\n",
				ino, file->name.len, file->name.name);
		return err;
	}

	list_add_tail(&reconcile_entry->reconcile_list, &symexec->reconcile_log);
	*/
	err = symexec_reconcile_log_put(symexec, ino, file, entry);
	if (err < 0) {
		BTRFS_SYM_DBG("LOG-PUT > Error\n");
		return err;
	}

out:
	return 0;
}

static int __symexec_apply_unlink(struct symexec_ctl * symexec,
		struct btrfs_acid_log_unlink * entry)
{
	if (!symexec || !entry
			|| ((entry->type != BTRFS_ACID_LOG_UNLINK)
					&& (entry->type != BTRFS_ACID_LOG_RMDIR)))
		return -EINVAL;

	return __symexec_apply_unlink_do(symexec, &entry->file,
			entry->nlink, (struct btrfs_acid_log_entry *) entry);
}

static int __symexec_apply_link_do(struct symexec_ctl * symexec,
		struct btrfs_acid_log_file * file, unsigned int nlink,
		struct btrfs_acid_log_entry * entry)
{
	int err;
	u64 parent;
	u64 ino;
	struct symexec_entry * dir_entry;

	if (!symexec || !file || !entry)
		return -EINVAL;

	err = __symexec_get_mapped(symexec,
			file->parent_location.objectid, &parent);
	if (err < 0) {
		BTRFS_SYM_DBG("parent ino: %llu; entry parent ino: %llu\n",
				parent, file->parent_location.objectid);
		return err;
	}

	err = __symexec_get_mapped(symexec, file->location.objectid, &ino);
	if (err < 0) {
		BTRFS_SYM_DBG("parent ino: %llu; ino: %llu\n",
				parent, ino);
		return err;
	}

	/* there is a valid mapping for ino */
	if (err) {
		err = symexec_nlinks_inc(symexec, ino);
		if (err < 0) {
			BTRFS_SYM_DBG("NLINKS-INC > parent: %llu; ino: %llu; name: %.*s\n",
					parent, ino, file->name.len, file->name.name);
			return err;
		}
	} else {
		err = symexec_nlinks_put(symexec, ino, nlink);
		if (err < 0) {
			BTRFS_SYM_DBG("NLINKS-PUT > parent: %llu; ino: %llu; name: %.*s\n",
					parent, ino, file->name.len, file->name.name);
			return err;
		}
	}

	dir_entry = __symexec_create_entry(ino, file, entry, ORIGIN_GLOBAL);
	if (IS_ERR(dir_entry)) {
		BTRFS_SYM_DBG("CREATE-ENTRY > parent: %llu; ino: %llu; name: %.*s\n",
				parent, ino, file->name.len, file->name.name);
		return PTR_ERR(dir_entry);
	}

	err = symexec_reconcile_log_put(symexec, ino, file, entry);
	if (err < 0) {
		BTRFS_SYM_DBG("LOG-PUT > Error\n");
		return err;
	}
// //	if (entry->type != BTRFS_ACID_LOG_RENAME)
//		list_add_tail(&dir_entry->reconcile_list, &symexec->reconcile_log);

	err = symexec_dir_put(symexec, parent, dir_entry);
	if (err < 0) {
		BTRFS_SYM_DBG("DIR-PUT > parent: %llu; ino: %llu; name: %.*s\n",
				parent, ino, file->name.len, file->name.name);
		return err;
	}

	err = symexec_dirty_dir_put(symexec, parent);
	if (err < 0) {
		BTRFS_SYM_DBG("DIRTY-PUT > parent: %llu\n", parent);
		return err;
	}

	return 0;
}

static int __symexec_apply_link(struct symexec_ctl * symexec,
		struct btrfs_acid_log_link * entry)
{
	if (!symexec || !entry || (entry->type != BTRFS_ACID_LOG_LINK))
		return -EINVAL;

	return __symexec_apply_link_do(symexec, &entry->new_file, entry->nlink,
			(struct btrfs_acid_log_entry *) entry);
}

static int __symexec_apply_rename(struct symexec_ctl * symexec,
		struct btrfs_acid_log_rename * entry)
{
	int err;

	if (!symexec || !entry)
		return -EINVAL;

#if 0
	if (((void *) entry->new_file->location) != NULL) {
		err = __symexec_apply_unlink_do(symexec, &entry->new_file,
				entry->new_file_nlink, (struct btrfs_acid_log_entry *) entry);
		if (err < 0) {
			BTRFS_SYM_DBG("TARGET-UNLINK-DO > name: %.*s\n",
					entry->new_file.name.len, entry->new_file.name.name);
			return err;
		}

	}
#endif

	if (entry->unlinked_file) {
		err = __symexec_apply_unlink_do(symexec, entry->unlinked_file,
				entry->unlinked_file_nlink,
				(struct btrfs_acid_log_entry *) entry);
		if (err < 0) {
			BTRFS_SYM_DBG("TARGET-UNLINK-DO > name: %.*s\n",
					entry->unlinked_file->name.len,
					entry->unlinked_file->name.name);
			return err;
		}
	}

	err = __symexec_apply_link_do(symexec, &entry->new_file, entry->nlink,
			(struct btrfs_acid_log_entry *) entry);
	if (err < 0) {
		BTRFS_SYM_DBG("LINK-DO > name: %.*s\n",
				entry->new_file.name.len, entry->new_file.name.name);
		return err;
	}

	err = __symexec_apply_unlink_do(symexec, &entry->old_file, entry->nlink,
			(struct btrfs_acid_log_entry *) entry);
	if (err < 0) {
		BTRFS_SYM_DBG("UNLINK-DO > name: %.*s\n",
				entry->old_file.name.len, entry->old_file.name.name);
		return err;
	}

	return 0;
}

static int __symexec_apply_write(struct symexec_ctl * symexec,
		struct btrfs_acid_log_rw * entry)
{
	int err;
	u64 ino;

	if (!symexec || !entry)
		return -EINVAL;

	err = __symexec_get_mapped(symexec, entry->file.location.objectid, &ino);
	if (err < 0) {
		BTRFS_SYM_DBG("ino: %llu, name: %.*s\n", ino,
				entry->file.name.len, entry->file.name.name);
		return err;
	}

	/* there is no valid mapping for ino; i.e., it was not created/linked
	 * during the symbolic execution. */
	if (!err) {
		err = symexec_nlinks_put(symexec, entry->ino, entry->nlink);
		if (err < 0) {
			BTRFS_SYM_DBG("NLINKS-PUT > ino: %llu; name: %.*s\n", ino,
					entry->file.name.len, entry->file.name.name);
			return err;
		}
		err = symexec_blocks_put(symexec, ino, entry, ORIGIN_GLOBAL);
		if (err < 0) {
			BTRFS_SYM_DBG("BLOCKS-PUT > ino: %llu; name: %.*s\n", ino,
					entry->file.name.len, entry->file.name.name);
			return err;
		}
	}

	// if the file was created during symexec, then we see no point in keeping
	// it in the log, as it will be reconciled with the snapshot on create
	// using extent magic.
//	err = symexec_blocks_put(symexec, ino, entry, ORIGIN_GLOBAL);
//	if (err < 0) {
//		BTRFS_SYM_DBG("BLOCKS-PUT > ino: %llu; name: %.*s\n", ino,
//				entry->file.name.len, entry->file.name.name);
//		return err;
//	}
	return 0;
}

/**
 * symexec_apply - Apply an operation log to our symbolic execution tree.
 *
 * Basically, this method should be used to apply the operations from the
 * master copy into our symbolic execution tree. These operations will be
 * applied following constraints required only by the master copy's logs, which
 * are different from those required by the snapshot's operations. Therefore,
 * we must use another method to apply the snapshot's operations.
 */
static int symexec_apply(struct symexec_ctl * symexec, struct list_head * log)
{
	struct list_head * log_item;
	struct btrfs_acid_log_entry * log_entry;
	int err = 0;


	if (!symexec || !log)
		return -EINVAL;

	if (list_empty(log))
		goto out;

	list_for_each(log_item, log) {
		log_entry = list_entry(log_item, struct btrfs_acid_log_entry, list);

		switch (log_entry->type) {
		case BTRFS_ACID_LOG_CREATE:
		case BTRFS_ACID_LOG_MKDIR:
		case BTRFS_ACID_LOG_SYMLINK:
		case BTRFS_ACID_LOG_MKNOD:
			err = __symexec_apply_create(symexec, (void *) log_entry);
			break;
		case BTRFS_ACID_LOG_UNLINK:
		case BTRFS_ACID_LOG_RMDIR:
			err = __symexec_apply_unlink(symexec, (void *) log_entry);
			break;
		case BTRFS_ACID_LOG_LINK:
			err = __symexec_apply_link(symexec, (void *) log_entry);
			break;
		case BTRFS_ACID_LOG_RENAME:
			err = __symexec_apply_rename(symexec, (void *) log_entry);
			break;
		case BTRFS_ACID_LOG_WRITE:
			err = __symexec_apply_write(symexec, (void *) log_entry);
			break;
		}
	}

out:
	return err;
}

static int __symexec_validate_create(struct symexec_ctl * symexec,
		struct btrfs_acid_log_create * entry)
{
	u64 parent, ino;
	struct symexec_entry * dir_entry;
	int err;

	if (!symexec || !entry)
		return -EINVAL;

	parent = entry->file.parent_location.objectid;
	ino = entry->file.location.objectid;

#if 0
	err = symexec_dir_match_file(symexec, parent, 0, &entry->file.name);
	if (err < 0) {
		BTRFS_SYM_DBG_FILE(&entry->file);
		return err;
	}

	if (err) { /* matched an entry */
		return SYMEXEC_CONFLICT;
	}
#endif

	dir_entry = symexec_dir_lookup_file(symexec, parent, 0,	&entry->file.name);
	if (IS_ERR(dir_entry)) {
		BTRFS_SYM_DBG("DIR-FIND-FILE > parent: %llu, ino: %llu, name: %.*s\n",
				parent, ino, entry->file.name.len, entry->file.name.name);
		return PTR_ERR(dir_entry);
	} else if (dir_entry) { /* matched */
		BTRFS_SYM_DBG("CONFLICT BETWEEN %.*s (local) and %.*s (global) "
				"on parent %llu\n",
				entry->file.name.len, entry->file.name.name,
				dir_entry->file->name.len, dir_entry->file->name.name,
				parent);
		return SYMEXEC_CONFLICT;
	}

	dir_entry = __symexec_create_entry(ino, &entry->file,
			(struct btrfs_acid_log_entry *) entry, ORIGIN_LOCAL);
	if (IS_ERR(dir_entry)) {
		BTRFS_SYM_DBG_FILE(&entry->file);
		return PTR_ERR(dir_entry);
	}

	err = symexec_dir_put(symexec, parent, dir_entry);
	if (err < 0) {
		BTRFS_SYM_DBG_FILE(&entry->file);
		return err;
	}

	err = symexec_nlinks_put(symexec, ino, 1);
	if (err < 0) {
		BTRFS_SYM_DBG_FILE(&entry->file);
		return err;
	}
	return SYMEXEC_OKAY;
}

static int __symexec_validate_unlink_do(struct symexec_ctl * symexec,
		struct btrfs_acid_log_file * file, unsigned int nlink,
		struct btrfs_acid_log_entry * entry)
{
	u64 parent, ino;
	u8 origin;
	struct qstr * name;
	struct symexec_entry * rem_entry;
	int err;

	if (!symexec || !file || !entry)
		return -EINVAL;

	parent = file->parent_location.objectid;
	ino = file->location.objectid;
	name = &file->name;

	err = symexec_rem_match_file(symexec, ino, parent, name, &origin);
	if (err < 0) {
		BTRFS_SYM_DBG("REM-MATCH-FILE > parent: %llu, ino: %llu, name: %.*s\n",
				parent, ino, name->len, name->name);
		return err;
	} else if (err) { /* matched */
		BTRFS_SYM_DBG("CONFLICT BETWEEN %.*s (local) and a %s entry "
				"on parent %llu\n",
				name->len, name->name,
				(origin == ORIGIN_GLOBAL ? "GLOBAL" : "LOCAL"),	parent);
		return SYMEXEC_CONFLICT;
	}

	err = symexec_dir_match_file(symexec, parent, ino, name, &origin);
	if (err < 0) {
		BTRFS_SYM_DBG("DIR-MATCH-FILE > parent: %llu, ino: %llu, name: %.*s\n",
				parent, ino, name->len, name->name);
		return err;
	} else if (err) { /* matched */
		if (origin != ORIGIN_LOCAL) {
			BTRFS_SYM_DBG("DIR-MATCH-FILE > ORIGIN: GLOBAL, parent: %llu,"
					"ino: %llu, name: %.*s\n",
					parent, ino, name->len, name->name);
			return -EINVAL;
		}

		err = symexec_dir_remove(symexec, parent, ino, name);
		if (err < 0) {
			BTRFS_SYM_DBG("DIR-REMOVE > parent: %llu, ino: %llu, name: %.*s\n",
					parent, ino, name->len, name->name);
			return err;
		}
		err = symexec_nlinks_dec(symexec, ino);
		if (err < 0) {
			BTRFS_SYM_DBG("NLINKS-DEC > parent: %llu, ino: %llu, name: %.*s\n",
					parent, ino, name->len, name->name);
			return err;
		}
	} else {
		rem_entry = __symexec_create_entry(parent, file, entry, ORIGIN_LOCAL);
		if (IS_ERR(rem_entry)) {
			BTRFS_SYM_DBG("CREATE-ENTRY > parent: %llu, ino: %llu, name: %.*s\n",
					parent, ino, name->len, name->name);
			return PTR_ERR(rem_entry);
		}
		err = symexec_rem_put(symexec, ino, rem_entry);
		if (err < 0) {
			BTRFS_SYM_DBG("REM-PUT> parent: %llu, ino: %llu, name: %.*s\n",
					parent, ino, name->len, name->name);
			return err;
		}
		err = symexec_nlinks_put(symexec, ino, nlink);
		if (err < 0) {
			BTRFS_SYM_DBG("NLINKS-PUT > parent: %llu, ino: %llu, name: %.*s\n",
					parent, ino, name->len, name->name);
			return err;
		}
	}

	return SYMEXEC_OKAY;
}

static int __symexec_validate_unlink(struct symexec_ctl * symexec,
		struct btrfs_acid_log_unlink * entry)
{
	if (!symexec || !entry)
		return -EINVAL;

	return __symexec_validate_unlink_do(symexec, &entry->file,
			entry->nlink, (struct btrfs_acid_log_entry *) entry);
}

static int __symexec_validate_link_do(struct symexec_ctl * symexec,
		struct btrfs_acid_log_file * old_file,
		struct btrfs_acid_log_file * new_file,
		unsigned int nlink,
		struct btrfs_acid_log_entry * entry)
{
	u64 old_parent, old_ino;
	u64 new_parent, new_ino;
	struct qstr * old_name, * new_name;
	u8 orig;
	struct symexec_nlinks_tree_entry * nlinks_entry;
	struct symexec_entry * dir_entry;
	int err;

	if (!symexec || !old_file || !new_file || !entry)
		return -EINVAL;

	old_parent = old_file->parent_location.objectid;
	old_ino = old_file->location.objectid;
	old_name = &old_file->name;
	new_parent = new_file->parent_location.objectid;
	new_ino = new_file->location.objectid;
	new_name = &new_file->name;

//	err = symexec_rem_match_file(symexec, old_parent, old_ino, old_name, &orig);
	err = symexec_rem_match_file(symexec, old_ino, old_parent, old_name, &orig);
	if (err < 0) {
		BTRFS_SYM_DBG("REM-MATCH-FILE > parent: %llu, ino: %llu, name: %.*s\n",
				old_parent, old_ino, old_name->len, old_name->name);
		return err;
	} else if (err) { /* matched */
		BTRFS_SYM_DBG("CONFLICT BETWEEN %.*s (local) and a %s entry "
				"on parent %llu: link's old file previously removed.\n",
				old_name->len, old_name->name,
				(orig == ORIGIN_GLOBAL ? "GLOBAL" : "LOCAL"), old_parent);
		return SYMEXEC_CONFLICT;
	}

	err = symexec_dir_match_file(symexec, new_parent, 0, new_name, &orig);
	if (err < 0) {
		BTRFS_SYM_DBG("DIR-MATCH-FILE > parent: %llu, ino: %llu, name: %.*s\n",
				new_parent, new_ino, new_name->len, new_name->name);
		return err;
	} else if (err) { /* matched */
		BTRFS_SYM_DBG("CONFLICT BETWEEN %.*s (local) and a %s entry "
				"on parent %llu: link's new file previously created.\n",
				new_name->len, new_name->name,
				(orig == ORIGIN_GLOBAL ? "GLOBAL" : "LOCAL"), old_parent);
		return SYMEXEC_CONFLICT;
	}

	dir_entry = __symexec_create_entry(new_ino, new_file, entry, ORIGIN_LOCAL);
	if (IS_ERR(dir_entry)) {
		BTRFS_SYM_DBG_FILE(new_file);
		return PTR_ERR(dir_entry);
	}
	err = symexec_dir_put(symexec, new_parent, dir_entry);
	if (err < 0) {
		BTRFS_SYM_DBG_FILE(new_file);
		return err;
	}

	nlinks_entry = symexec_nlinks_get_entry(symexec, old_ino);
	if (IS_ERR(nlinks_entry)) {
		BTRFS_SYM_DBG("NLINKS-GET-ENTRY > parent: %llu, ino: %llu, name: %.*s\n",
				old_parent, old_ino, old_name->len, old_name->name);
		return err;
	} else if (!nlinks_entry) {
		err = symexec_nlinks_put(symexec, old_ino, nlink);
		if (err < 0) {
			BTRFS_SYM_DBG("NLINKS-PUT > ino: %llu, nlink: %d\n",
					old_ino, nlink);
			return err;
		}
	} else {
		err = symexec_nlinks_inc(symexec, old_ino);
		if (err < 0) {
			BTRFS_SYM_DBG("NLINKS-INC > ino: %llu\n", old_ino);
			return err;
		}
	}

	return SYMEXEC_OKAY;
}

static int __symexec_validate_link(struct symexec_ctl * symexec,
		struct btrfs_acid_log_link * entry)
{
	if (!symexec || !entry)
		return -EINVAL;
	return __symexec_validate_link_do(symexec, &entry->old_file,
			&entry->new_file, entry->nlink,
			(struct btrfs_acid_log_entry *) entry);

}

static int __symexec_validate_rename(struct symexec_ctl * symexec,
		struct btrfs_acid_log_rename * entry)
{
	int err;

	if (!symexec || !entry)
		return -EINVAL;

	if (entry->unlinked_file) {
		err = __symexec_validate_unlink_do(symexec, entry->unlinked_file,
				entry->unlinked_file_nlink,
				(struct btrfs_acid_log_entry *) entry);
		if (err < 0) {
			BTRFS_SYM_DBG("TARGET-UNLINK-DO > name: %.*s\n",
					entry->unlinked_file->name.len,
					entry->unlinked_file->name.name);
			return err;
		}
	}

	err = __symexec_validate_link_do(symexec, &entry->old_file,
			&entry->new_file, entry->nlink,
			(struct btrfs_acid_log_entry *) entry);
	if (err < 0) {
		BTRFS_SYM_DBG("LINK-DO > old name: %.*s; new name: %.*s\n",
				entry->old_file.name.len, entry->old_file.name.name,
				entry->new_file.name.len, entry->new_file.name.name);
		return err;
	}

	err = __symexec_validate_unlink_do(symexec, &entry->old_file,
			entry->nlink, (struct btrfs_acid_log_entry *) entry);
	if (err < 0) {
		BTRFS_SYM_DBG("UNLINK-DO > name: %.*s\n",
				entry->old_file.name.len, entry->old_file.name.name);
		return err;
	}

	return SYMEXEC_OKAY;
}

static int __symexec_validate_readdir(struct symexec_ctl * symexec,
		struct btrfs_acid_log_readdir * entry)
{
	u64 ino;
	struct qstr * name;
//	struct list_head * lst;
//	struct symexec_entry * dir_entry;
	struct symexec_entry * rem_entry;
	int err;

	if (!symexec || !entry)
		return -EINVAL;

	/* Please, don't forget: this method checks whether a directory was changed,
	 * in which case the readdir operation would be in conflict. This means we
	 * ought to check if there are any entries such that their parent inode
	 * value is the same as this directory's inode value.
	 */
	ino = entry->file.location.objectid;
	name = &entry->file.name;

#if 0
	lst = __list_tree_get(&symexec->dir, ino);
	if (IS_ERR(lst)) {
		BTRFS_SYM_DBG("TREE-GET > ino: %llu\n", ino);
		return PTR_ERR(lst);
	} else if (!lst)
		goto validate_rem;

	list_for_each_entry(dir_entry, lst, list) {
		if (dir_entry->origin == ORIGIN_GLOBAL) {
			BTRFS_SYM_DBG("CONFLICT BETWEEN %.*s (local ino: %llu) "
					"and GLOBAL entry %.*s: directory previously changed.\n",
					name->len, name->name, ino,
					entry->file.name.len, entry->file.name.name);
			return SYMEXEC_CONFLICT;
		}
	}
#endif

	err = symexec_dirty_dir_contains(symexec, ino);
	if (err < 0) {
		BTRFS_SYM_DBG("DIRTY-CONTAINS > ino: %llu\n", ino);
		return err;
	} else if (err) {
		BTRFS_SYM_DBG("CONFLICT ON %.*s (local ino: %llu): "
				"directory previously changed.\n",
				name->len, name->name, ino);
		return SYMEXEC_CONFLICT;
	}

	rem_entry = symexec_rem_lookup_file(symexec, ino, 0, name);
	if (IS_ERR(rem_entry)) {
		BTRFS_SYM_DBG("REM-LOOKUP > ino: %llu, name: %.*s\n",
				ino, name->len, name->name);
		return PTR_ERR(rem_entry);
	} else if (rem_entry != NULL) {
		BTRFS_SYM_DBG("CONFLICT ON %.*s (local ino: %llu): "
				"directory previously removed.\n",
				name->len, name->name, ino);
		return SYMEXEC_CONFLICT; // this should be taken with a grain of salt.
	}

	return SYMEXEC_OKAY;
}

static int __symexec_validate_truncate(struct symexec_ctl * symexec,
		struct btrfs_acid_log_truncate * entry)
{
	u64 parent, ino;
	struct qstr * name;
	struct list_head * lst;
//	struct symexec_entry * rem_entry;
	struct symexec_blocks_truncate * trunc_entry;
	u8 orig;
	int err;

	if (!symexec || !entry)
		return -EINVAL;

	ino = entry->ino;
	parent = entry->file.parent_location.objectid;
	name = &entry->file.name;

	err = symexec_rem_match_file(symexec, ino, parent, name, &orig);
	if (err < 0) {
		BTRFS_SYM_DBG("REM-MATCH-FILE > parent: %llu, ino: %llu, name: %.*s\n",
				parent, ino, name->len, name->name);
		return err;
	} else if (err) { /* matched */
		BTRFS_SYM_DBG("CONFLICT BETWEEN %.*s (local) and a %s entry "
				"on parent %llu: file to truncate previously removed.\n",
				name->len, name->name,
				(orig == ORIGIN_GLOBAL ? "GLOBAL" : "LOCAL"), parent);
		return SYMEXEC_CONFLICT;
	}

#if 0
	lst = symexec_rem_get(symexec, ino);
	if (IS_ERR(lst)) {
		BTRFS_SYM_DBG("REM-GET > ino: %llu\n", ino);
		return PTR_ERR(lst);
	} else if (lst == NULL)
		goto validate_blocks;

	list_for_each_entry(rem_entry, lst, list) {
		if (rem_entry->origin == ORIGIN_GLOBAL) {
			BTRFS_SYM_DBG("CONFLICT ON TRUNCATE ino: %llu WITH %.*s (p: %llu): "
					"file previously removed.\n",
					ino, rem_entry->file->name.len, rem_entry->file->name.name,
					rem_entry->file->parent_location.objectid);
			return SYMEXEC_CONFLICT;
		}
	}
validate_blocks:
#endif

	lst = symexec_blocks_get(symexec, ino);
	if (IS_ERR(lst)) {
		BTRFS_SYM_DBG("BLOCKS-GET > ino: %llu\n", ino);
		return PTR_ERR(lst);
	}

	trunc_entry = kzalloc(sizeof(*trunc_entry), GFP_NOFS);
	if (!trunc_entry)
		return -ENOMEM;

	err = __symexec_fill_entry((struct symexec_entry *) trunc_entry, ino,
			&entry->file, (struct btrfs_acid_log_entry *) entry, ORIGIN_LOCAL);
	if (err < 0) {
		BTRFS_SYM_DBG("FILL-ENTRY > ino: %llu, file: %p, entry: %p\n",
				ino, &entry->file, entry);
		return err;
	}
	if (!lst || list_empty(lst))
			goto insert_entry;

	list_replace_init(lst, &trunc_entry->truncated_blocks_list);
	list_add_tail(&trunc_entry->list, lst);
	return SYMEXEC_OKAY;

insert_entry:
#if 0
	err = symexec_blocks_put(symexec, ino,
			(struct btrfs_acid_log_rw *) entry, ORIGIN_LOCAL);
#endif
	BTRFS_SYM_DBG("PUTTING INTO BLOCKS TREE\n");
	INIT_LIST_HEAD(&trunc_entry->truncated_blocks_list);
	err = __list_tree_put(&symexec->blocks, ino,
			(struct symexec_entry *) trunc_entry);
	if (err < 0) {
		BTRFS_SYM_DBG("BLOCKS-PUT > ino: %llu, entry: %p\n", ino, entry);
		return err;
	}

	return SYMEXEC_OKAY;
}

static int __symexec_validate_write(struct symexec_ctl * symexec,
		struct btrfs_acid_log_rw * entry)
{
	u64 parent, ino;
	struct qstr * name;
	u8 origin;
	int err;

	if (!symexec || !entry)
		return -EINVAL;

	parent = entry->file.parent_location.objectid;
	ino = entry->file.location.objectid;
	name = &entry->file.name;

	err = symexec_rem_match_file(symexec, ino, parent, name, &origin);
	if (err < 0) {
		BTRFS_SYM_DBG("REM-MATCH-FILE > parent: %llu, ino: %llu, name: %.*s\n",
				parent, ino, name->len, name->name);
		return err;
	} else if (err) { /* matched */
		BTRFS_SYM_DBG("CONFLICT BETWEEN %.*s (local) and a %s entry "
				"on parent %llu: file to write previously removed.\n",
				name->len, name->name,
				(origin == ORIGIN_GLOBAL ? "GLOBAL" : "LOCAL"), parent);
		return SYMEXEC_CONFLICT;
	}

	err = symexec_nlinks_contains(symexec, ino);
	if (err < 0) {
		BTRFS_SYM_DBG("NLINKS-CONTAINS > ino: %llu\n", ino);
	} else if (!err) {
		err = symexec_nlinks_put(symexec, ino, entry->nlink);
		if (err < 0) {
			BTRFS_SYM_DBG("NLINKS-PUT > ino: %llu\n", ino);
		}
	}
	return (err < 0 ? err : SYMEXEC_OKAY);
}

static int __check_rw_overlap(struct btrfs_acid_log_rw * a,
		struct btrfs_acid_log_rw * b)
{
	struct btrfs_acid_log_rw * first, * last;

	if (!a || !b)
		return -EINVAL;

	if (a->first_page < b->first_page) {
		first = a;
		last = b;
	} else {
		first = b;
		last = a;
	}

	return ((last->first_page >= first->first_page)
			&& (last->first_page <= first->last_page));
}

static int __symexec_validate_read(struct symexec_ctl * symexec,
		struct btrfs_acid_log_rw * entry)
{
	u64 parent, ino;
	struct qstr * name;
	struct list_head * lst;
	struct symexec_entry * symexec_entry;
	struct btrfs_acid_log_rw * rw_entry;
	struct btrfs_acid_log_truncate * trunc_entry;
	u8 origin;
	int err;

	if (!symexec || !entry)
		return -EINVAL;

	parent = entry->file.parent_location.objectid;
	ino = entry->file.location.objectid;
	name = &entry->file.name;

	err = symexec_rem_match_file(symexec, ino, parent, name, &origin);
	if (err < 0) {
		BTRFS_SYM_DBG("REM-MATCH-FILE > parent: %llu, ino: %llu, name: %.*s\n",
				parent, ino, name->len, name->name);
		return err;
	} else if (err) { /* matched */
		BTRFS_SYM_DBG("CONFLICT BETWEEN %.*s (local) and a %s entry "
				"on parent %llu: file to read previously removed.\n",
				name->len, name->name,
				(origin == ORIGIN_GLOBAL ? "GLOBAL" : "LOCAL"), parent);
		return SYMEXEC_CONFLICT;
	}

	lst = symexec_blocks_get(symexec, ino);
	if (IS_ERR(lst)) {
		BTRFS_SYM_DBG("BLOCKS-GET > ino: %llu\n", ino);
		return PTR_ERR(lst);
	} else if (!lst || list_empty(lst))
		goto out_okay;

	list_for_each_entry(symexec_entry, lst, list) {
		if (symexec_entry->log_entry->type == BTRFS_ACID_LOG_TRUNCATE) {
			/* ignore all truncates locally added as those won't
			 * be relevant to us */
			if (symexec_entry->origin == ORIGIN_LOCAL)
				continue;

			trunc_entry = (struct btrfs_acid_log_truncate *)
					symexec_entry->log_entry;

			if ((entry->first_page >= trunc_entry->from)
					|| (entry->last_page >= trunc_entry->from)) {
				BTRFS_SYM_DBG("CONFLICT BETWEEN %.*s (local) and %.*s (%s) "
						"on parent %llu: "
						"read pages [%lu, %lu], truncate from page %lu\n",
						name->len, name->name,
						trunc_entry->file.name.len, trunc_entry->file.name.name,
						(symexec_entry->origin == ORIGIN_GLOBAL ?
								"GLOBAL" : "LOCAL"), parent,
						entry->first_page, entry->last_page,
						trunc_entry->from);
				return SYMEXEC_CONFLICT;
			}
			continue;
		}

		rw_entry = (struct btrfs_acid_log_rw *) symexec_entry->log_entry;
		err = __check_rw_overlap(entry, rw_entry);
		if (err < 0) {
			BTRFS_SYM_DBG("CHECK-RW-OVERLAP > entry: %p, rw_entry: %p\n",
					entry, rw_entry);
			return err;
		} else if (err != 0) {
			BTRFS_SYM_DBG("CONFLICT BETWEEN %.*s (local) and %.*s (%s) "
					"on parent %llu: "
					"read pages [%lu, %lu], write page [%lu, %lu]\n",
					name->len, name->name,
					rw_entry->file.name.len, rw_entry->file.name.name,
					(symexec_entry->origin == ORIGIN_GLOBAL ?
							"GLOBAL" : "LOCAL"),
					parent,
					entry->first_page, entry->last_page,
					rw_entry->first_page, rw_entry->last_page);
			return SYMEXEC_CONFLICT;
		}
	}

out_okay:
	return SYMEXEC_OKAY;
}

/**
 * symexec_validate - Validates a snapshot's operation log against a
 * symbolic execution.
 *
 */
static int symexec_validate(struct symexec_ctl * symexec,
		struct btrfs_acid_snapshot * snap)
{
	struct list_head * log_item;
	struct btrfs_acid_log_entry * entry;
	int err;
	int stats_processed_ops = 0;

	if (!symexec)
		return -EINVAL;

	if (list_empty(&snap->op_log)) {
		BTRFS_SYM_DBG("Snapshot's Operation Log is EMPTY\n");
		goto out;
	}

	list_for_each(log_item, &snap->op_log) {
		entry = list_entry(log_item, struct btrfs_acid_log_entry, list);

		switch (entry->type) {
		case BTRFS_ACID_LOG_CREATE:
		case BTRFS_ACID_LOG_MKDIR:
		case BTRFS_ACID_LOG_MKNOD:
		case BTRFS_ACID_LOG_SYMLINK:
			err = __symexec_validate_create(symexec, (void *) entry);
			break;
		case BTRFS_ACID_LOG_UNLINK:
		case BTRFS_ACID_LOG_RMDIR:
			err = __symexec_validate_unlink(symexec, (void *) entry);
			break;
		case BTRFS_ACID_LOG_LINK:
			err = __symexec_validate_link(symexec, (void *) entry);
			break;
		case BTRFS_ACID_LOG_RENAME:
			err = __symexec_validate_rename(symexec, (void *) entry);
			break;
		case BTRFS_ACID_LOG_READDIR:
			err = __symexec_validate_readdir(symexec, (void *) entry);
			break;
		case BTRFS_ACID_LOG_TRUNCATE:
			BTRFS_SYM_DBG("<MISSING> TRUNCATE VALIDATION IS INCORRECT!\n");
			err = __symexec_validate_truncate(symexec, (void *) entry);
			break;
		case BTRFS_ACID_LOG_WRITE:
			BTRFS_SYM_DBG("<MISSING> WRITE VALIDATION: Delta M's truncates.\n");
			err = __symexec_validate_write(symexec, (void *) entry);
			break;
		case BTRFS_ACID_LOG_READ:
			err = __symexec_validate_read(symexec, (void *) entry);
			break;
		}

		if (err < 0)
			break;
		stats_processed_ops ++;
	}

	BTRFS_SYM_PRINT("Total Processed ops = %d\n", stats_processed_ops);
out:
	return err;
}

static int __symexec_reconcile_link_do(struct btrfs_trans_handle * trans,
		struct btrfs_acid_snapshot * txsv,
		struct btrfs_acid_snapshot * snap, struct inode * dir,
		u64 ino, struct btrfs_acid_log_file * file);
static int __symexec_reconcile_unlink_do(struct btrfs_trans_handle * trans,
		struct btrfs_acid_snapshot * txsv,
		struct btrfs_acid_snapshot * snap, struct inode * dir, u64 ino,
		struct btrfs_acid_log_file * file, int record_dir, u8 type);

static int __symexec_reconcile_rename(struct btrfs_trans_handle * trans,
		struct symexec_ctl * symexec,
		struct btrfs_acid_snapshot * txsv,
		struct btrfs_acid_snapshot * snap, struct inode * dir,
		struct symexec_entry * entry)
{
	struct btrfs_acid_log_rename * rename_entry;
	struct inode * old_dir, * new_dir;
	u64 old_dir_ino;
//	u64 new_dir_ino;
	int err = 0;
	struct super_block * sb;
	struct btrfs_key key;

	u64 unlinked_ino;
//	struct inode * unlinked_inode;
	int put_old_dir = 0;

	u64 old_ino;
	int old_ino_mapped = 0;
//	unsigned int old_ino_nlinks;

	if (!trans || !txsv || !snap || !dir || !entry)
		return -EINVAL;

	sb = snap->root->fs_info->sb;
	rename_entry = (struct btrfs_acid_log_rename *) entry->log_entry;

	new_dir = dir;

	old_dir_ino = rename_entry->old_file.parent_location.objectid;
	err = __symexec_get_mapped(symexec, old_dir_ino, &old_dir_ino);
	if (err < 0) {
		BTRFS_SYM_DBG("GET-MAPPED > Error > old dir ino: %llu\n", old_dir_ino);
		return err;
	} else {
		if (old_dir_ino != dir->i_ino) {
			key.objectid = old_dir_ino;
			key.type = BTRFS_INODE_ITEM_KEY;
			key.offset = 0;
			old_dir = btrfs_iget(sb, &key, snap->root, NULL);
			if (!old_dir) {
				BTRFS_SYM_DBG("INODE-GET > Error > old dir: %llu\n", old_dir_ino);
				return PTR_ERR(old_dir);
			}
			put_old_dir = 1;
		} else
			old_dir = new_dir;
	}

	if (rename_entry->unlinked_file) {
		unlinked_ino = rename_entry->unlinked_file->location.objectid;
		err = __symexec_get_mapped(symexec, unlinked_ino, &unlinked_ino);
		if (err < 0) {
			BTRFS_SYM_DBG("GET-MAPPED > Error > ino: %llu\n", unlinked_ino);
			return err;
//		} else if (err) {
//			/* The file was created in the master copy, and unlinked on rename.
//			 * We have no use for it.
//			 */
		} else {
			err = __symexec_reconcile_unlink_do(trans, txsv, snap, dir,
					unlinked_ino,
					rename_entry->unlinked_file, 0, BTRFS_ACID_LOG_RENAME);
			if (err < 0) {
				BTRFS_SYM_DBG("UNLINK-DO > Error > dir: %llu, ino: %llu\n",
						dir->i_ino, unlinked_ino);
				if (put_old_dir)
					iput(old_dir);
				return err;
			}
			BTRFS_SYM_DBG("UNLINKED FILE > name: %.*s, dir: %llu, ino: %lu\n",
					rename_entry->unlinked_file->name.len,
					rename_entry->unlinked_file->name.name,
					dir->i_ino, unlinked_ino);
		}
	}

	old_ino = rename_entry->old_file.location.objectid;
	err = __symexec_get_mapped(symexec, old_ino, &old_ino);
	if (err < 0) {
		BTRFS_SYM_DBG("GET-MAPPED > Error > old ino: %llu\n", old_ino);
		if (put_old_dir)
			iput(old_dir);
		return err;
	} else if (err)
		old_ino_mapped = 1;

	if (old_ino != entry->ino) {
		WARN_ON(old_ino != entry->ino);
		if (put_old_dir)
			iput(old_dir);
		return -1;
	}

//	if (old_ino_mapped) {
//		err = symexec_nlinks_get(symexec, old_ino, &old_ino_nlinks);
//		if (err < 0) {
//			BTRFS_SYM_DBG("GET-NLINKS > old ino: %llu\n", old_ino);
//			if (put_old_dir)
//				iput(old_dir);
//			return err;
//		}
//		if (old_ino_nlinks > 1) {
	err = __symexec_reconcile_link_do(trans, txsv, snap,
			new_dir, old_ino, entry->file);
	if (err < 0) {
		BTRFS_SYM_DBG("LINK-DO > dir: %lu, ino: %llu, name: %.*s\n",
				new_dir->i_ino, old_ino,
				entry->file->name.len, entry->file->name.name);
		if (put_old_dir)
			iput(old_dir);
		return err;
	}
//		}
//	else {
//			err = __symexec_reconcile_
//		}
//	}

	err = __symexec_reconcile_unlink_do(trans, txsv, snap, old_dir, old_ino,
			&rename_entry->old_file, put_old_dir, BTRFS_ACID_LOG_RENAME);
	if (err < 0) {
		BTRFS_SYM_DBG("UNLINK-DO > old dir: %lu, ino: %llu, name: %.*s\n",
				old_dir->i_ino, old_ino,
				entry->file->name.len, entry->file->name.name);
		if (put_old_dir)
			iput(old_dir);
		return err;
	}

	BTRFS_SYM_DBG("RENAME > Success!\n");

	if (put_old_dir)
		iput(old_dir);
	return 0;


#if 0
	rename_entry = (struct btrfs_acid_log_rename *) entry->log_entry;

	old_dir_ino = rename_entry->old_file.parent_location.objectid;
	new_dir_ino = rename_entry->new_file.parent_location.objectid;

	if (rename_entry->unlinked_file) {
		err = __symexec_reconcile_unlink_do(trans, txsv, snap, new_dir,
				rename_entry->unlinked_file, 0, BTRFS_ACID_LOG_RENAME);
		if (err < 0) {
			BTRFS_SYM_DBG("UNLINK-DO > Error\n");
			return err;
		}
	}
	return err;
#endif

}

static int __symexec_reconcile_rmdir(struct btrfs_trans_handle * trans,
		struct btrfs_acid_snapshot * txsv,
		struct btrfs_acid_snapshot * snap, struct inode * dir,
		struct symexec_entry * entry)
{

	struct qstr * name;
	struct inode * inode;

	int err = 0;

	if (!trans || !txsv || !snap || !dir || !entry)
		return -EINVAL;

	if (entry->log_entry->type != BTRFS_ACID_LOG_RMDIR)
		return -EINVAL;

//	trans->block_rsv = &snap->root->fs_info->global_block_rsv;

	name = &entry->file->name;

	inode = btrfs_iget(snap->root->fs_info->sb, &entry->file->location,
			snap->root, NULL);
	if (IS_ERR_OR_NULL(inode))
		return PTR_ERR(inode);

//	err = btrfs_orphan_add(trans, inode);
//	if (err)
//		goto out;

	err = btrfs_unlink_inode(trans, snap->root, dir, inode,
			name->name, name->len);
	if (!err)
		btrfs_i_size_write(inode, 0);
	else {
		BTRFS_SYM_DBG("UNLINK-INODE > Error > d: %llu, ino: %llu, name: %.*s\n",
				dir->i_ino, inode->i_ino, name->len, name->name);
	}
//out:
	iput(inode);

//	btrfs_add_delayed_iput(inode);
	return err;
}

static int __symexec_reconcile_unlink_do(struct btrfs_trans_handle * trans,
		struct btrfs_acid_snapshot * txsv,
		struct btrfs_acid_snapshot * snap, struct inode * dir, u64 ino,
		struct btrfs_acid_log_file * file, int record_dir, u8 type)
{
	struct qstr * name;
	struct inode * inode;
	int is_rename = 0;
	int err = 0;
	struct btrfs_key ino_key;

	is_rename = (type == BTRFS_ACID_LOG_RENAME);

	name = &file->name;

	BTRFS_SYM_DBG("UNLINK-DO > trans: %p, txsv: %p, snap: %p, "
			"dir: %p, file: %p", trans, txsv, snap, dir, file);
	BTRFS_SYM_DBG("UNLINK-DO > file name: %.*s, name: %p\n",
			file->name.len, file->name.name, name);

//	trans = btrfs_start_transaction(snap->root, 0);
//	if (IS_ERR(*trans)) {
//		BTRFS_SYM_DBG("START-TRANS > Error\n");
//		return PTR_ERR(*trans);
//	}
//	*trans->block_rsv = &snap->root->fs_info->global_block_rsv;

	ino_key.objectid = ino;
	ino_key.type = BTRFS_INODE_ITEM_KEY;
	ino_key.offset = 0;

//	inode = btrfs_iget(snap->root->fs_info->sb, &file->location,
	inode = btrfs_iget(snap->root->fs_info->sb, &ino_key,
			snap->root, NULL);
	if (IS_ERR_OR_NULL(inode))
		return PTR_ERR(inode);

	if (record_dir)
		btrfs_record_unlink_dir(trans, dir, inode, is_rename);

	err = btrfs_unlink_inode(trans, snap->root, dir, inode,
			name->name, name->len);
	BUG_ON(err);

	if (inode->i_nlink == 0) {
		if (trans->block_rsv)
			BTRFS_SYM_DBG("ORPHAN > blk rsv: %llu\n",
				trans->block_rsv->reserved);
		else
			BTRFS_SYM_DBG("ORPHAN > blk rsv: NULL\n");

		err = btrfs_orphan_add(trans, inode);
		BUG_ON(err);
	}

	return err;
}

static int __symexec_reconcile_unlink(struct btrfs_trans_handle * trans,
		struct btrfs_acid_snapshot * txsv,
		struct btrfs_acid_snapshot * snap, struct inode * dir,
		struct symexec_entry * entry)
{

//	struct btrfs_acid_log_unlink * unlink_entry;
//	struct qstr * name;
//	struct inode * inode;
//	int is_unlink = 0;

//	int err = 0;

	if (!trans || !txsv || !snap || !dir || !entry)
		return -EINVAL;

	if ((entry->log_entry->type != BTRFS_ACID_LOG_UNLINK))
//			&& (entry->log_entry->type != BTRFS_ACID_LOG_RMDIR))
		return -EINVAL;
//	trans->block_rsv = &snap->root->fs_info->global_block_rsv;

	/* record dir; not the result of a rename operation */
	return __symexec_reconcile_unlink_do(trans, txsv, snap,
			dir, entry->ino, entry->file, 1, BTRFS_ACID_LOG_UNLINK);

#if 0
//	unlink_entry = (struct btrfs_acid_log_unlink *) entry->log_entry;
	name = &entry->file->name;

	inode = btrfs_iget(snap->root->fs_info->sb, &entry->file->location,
			snap->root, NULL);
	if (IS_ERR_OR_NULL(inode))
		return PTR_ERR(inode);

	btrfs_record_unlink_dir(trans, dir, inode, 0);

	err = btrfs_unlink_inode(trans, snap->root, dir, inode,
			name->name, name->len);
	BUG_ON(err);

	if (inode->i_nlink == 0) {
		err = btrfs_orphan_add(trans, inode);
		BUG_ON(err);
	}

//	nr = trans->blocks_used;
//	__unlink_end_trans(trans, root);
//	btrfs_btree_balance_dirty(root, nr);
	return err;
#endif
}

static int __symexec_reconcile_mknod(struct btrfs_trans_handle * trans,
		struct btrfs_acid_snapshot * txsv,
		struct btrfs_acid_snapshot * snap, struct inode * dir,
		struct symexec_entry * entry)
{
	struct btrfs_acid_log_mknod * mknod_entry;
	struct inode * inode;
	struct qstr * name;
	u64 index;
	int err;
	int drop_inode = 0;

	if (!trans || !txsv || !snap || !dir || !entry)
		return -EINVAL;

	mknod_entry = (struct btrfs_acid_log_mknod *) entry->log_entry;
	name = &mknod_entry->file.name;

	inode = btrfs_new_inode(trans, snap->root, dir,
				name->name, name->len, dir->i_ino,
				entry->ino, BTRFS_I(dir)->block_group,
				mknod_entry->mode, &index);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	err = btrfs_init_inode_security(trans, inode, dir);
	if (err < 0) {
		drop_inode = 1;
		goto out_unlock;
	}

	btrfs_set_trans_block_group(trans, inode);
	err = btrfs_add_link(trans, dir, inode, name->name, name->len, 0, index);
	if (err) {
		drop_inode = 1;
		goto out_unlock;
	}

	inode->i_op = &btrfs_acid_special_inode_operations;
	init_special_inode(inode, inode->i_mode, mknod_entry->rdev);
	btrfs_update_inode(trans, snap->root, inode);

	btrfs_update_inode_block_group(trans, inode);
	btrfs_update_inode_block_group(trans, dir);

out_unlock:
	if (drop_inode) {
		inode_dec_link_count(inode);
	}
	iput(inode);

	return err;
}

static int __symexec_reconcile_link_do(struct btrfs_trans_handle * trans,
		struct btrfs_acid_snapshot * txsv,
		struct btrfs_acid_snapshot * snap, struct inode * dir,
		u64 ino, struct btrfs_acid_log_file * file)
{
	struct qstr * name;
	struct inode * inode;
	u64 index;

	struct btrfs_key snap_ino_key;
	int drop_inode = 0;

	int err = 0;

	name = &file->name;

//	snap_ino_key.objectid = entry->ino;
	snap_ino_key.objectid = ino;
	snap_ino_key.type = BTRFS_INODE_ITEM_KEY;
	snap_ino_key.offset = 0;

	inode = btrfs_iget(snap->root->fs_info->sb,
			&snap_ino_key, snap->root, NULL);
	if (IS_ERR_OR_NULL(inode)) {
		BTRFS_SYM_DBG("INODE-GET > Error obtaining %llu\n", ino);
		return PTR_ERR(inode);
	}

	btrfs_inc_nlink(inode);
//	atomic_inc(&inode->i_count);

	err = btrfs_set_inode_index(dir, &index);
	if (err < 0)
		goto out;

	err = btrfs_add_link(trans, dir, inode, name->name, name->len, 1, index);
	if (err < 0) {
		drop_inode = 1;
		goto out;
	}

//	struct dentry *parent = dget_parent(dentry);
	btrfs_update_inode_block_group(trans, dir);
	err = btrfs_update_inode(trans, snap->root, inode);
	if (err) {
		BTRFS_SYM_DBG("UPDATE-INODE > inode: %p, inode i_ino: %llu, ino: %llu, "
				"dir: %llu, name: %.*s, btrfs inode: %p, "
				"location: [%llu %d %llu]\n",
				inode, inode->i_ino, ino, dir->i_ino,
				name->len, name->name, BTRFS_I(inode),
				BTRFS_I(inode)->location.objectid,
				BTRFS_I(inode)->location.type,
				BTRFS_I(inode)->location.offset);
	}
	BUG_ON(err);
//	btrfs_log_new_name(trans, inode, NULL, parent);
//	dput(parent);

out:
	if (drop_inode) {
		BTRFS_SYM_DBG("DROP INODE > DEC LINK COUNT for ino %llu\n",
				inode->i_ino);
		inode_dec_link_count(inode);
	}
	iput(inode);

	return err;
}

static int __symexec_reconcile_link(struct btrfs_trans_handle * trans,
		struct btrfs_acid_snapshot * txsv,
		struct btrfs_acid_snapshot * snap, struct inode * dir,
		struct symexec_entry * entry)
{
//	struct btrfs_acid_log_link * link_entry;
//	struct qstr * name;
//	struct inode * inode;
//	u64 index;

//	struct btrfs_key snap_ino_key;
//	int drop_inode = 0;

//	int err;

	if (!trans || !txsv || !snap || !dir || !entry)
		return -EINVAL;

	return __symexec_reconcile_link_do(trans, txsv, snap, dir,
			entry->ino, entry->file);
#if 0
	name = &entry->file->name;

	snap_ino_key.objectid = entry->ino;
	snap_ino_key.type = BTRFS_INODE_ITEM_KEY;
	snap_ino_key.offset = 0;

	inode = btrfs_iget(snap->root->fs_info->sb,
			&snap_ino_key, snap->root, NULL);
	if (IS_ERR_OR_NULL(inode)) {
		BTRFS_SYM_DBG("INODE-GET > Error obtaining %llu\n", entry->ino);
		return PTR_ERR(inode);
	}

	btrfs_inc_nlink(inode);
//	atomic_inc(&inode->i_count);

	err = btrfs_set_inode_index(dir, &index);
	if (err < 0)
		goto out;

	err = btrfs_add_link(trans, dir, inode, name->name, name->len, 1, index);
	if (err < 0) {
		drop_inode = 1;
		goto out;
	}

//	struct dentry *parent = dget_parent(dentry);
	btrfs_update_inode_block_group(trans, dir);
	err = btrfs_update_inode(trans, snap->root, inode);
	BUG_ON(err);
//	btrfs_log_new_name(trans, inode, NULL, parent);
//	dput(parent);

out:
	if (drop_inode) {
		BTRFS_SYM_DBG("DROP INODE > DEC LINK COUNT for ino %llu\n",
				inode->i_ino);
		inode_dec_link_count(inode);
	}
	iput(inode);

	return err;
#endif
}


void btrfs_set_inode_extent_io_ops(struct inode * inode);
void btrfs_set_inode_aops(struct inode * inode);


static int __symexec_reconcile_create(struct btrfs_trans_handle * trans,
		struct btrfs_acid_snapshot * txsv,
		struct btrfs_acid_snapshot * snap, struct inode * dir,
		struct symexec_entry * entry)
{
	struct btrfs_acid_log_create * create_entry;
	struct qstr * name;
	struct inode * inode;
	u64 index;
	int drop_inode = 0;

	struct extent_buffer * leaf;
	int slot;
	struct btrfs_path * path;
	struct btrfs_path * snap_path;
	char * buf;
	u32 size;
	struct btrfs_key item_key;
	struct btrfs_disk_key disk_key;
	u64 original_ino;
	struct btrfs_trans_handle * inner_trans;
	struct inode * original_inode;
	struct btrfs_key * original_location;
	struct btrfs_file_extent_item * ei;
	u64 item_numbytes, item_bytenr, item_offset;
	u8 item_type;

	struct btrfs_acid_log_symlink * symlink_entry;
	int new_inode_mode;

	int err, ret;

	if (!trans || !txsv || !snap || !dir || !entry)
		return -EINVAL;

	if ((entry->log_entry->type != BTRFS_ACID_LOG_CREATE)
			&& (entry->log_entry->type != BTRFS_ACID_LOG_SYMLINK))
		return -EINVAL;

	name = &entry->file->name;

	if (entry->log_entry->type == BTRFS_ACID_LOG_CREATE) {
		create_entry = (struct btrfs_acid_log_create *) entry->log_entry;
		original_location = &create_entry->file.location;
//		new_inode_mode = create_entry->mode;
	} else {
		symlink_entry = (struct btrfs_acid_log_symlink *) entry->log_entry;
		original_location = &symlink_entry->file.location;
	}

	original_inode = btrfs_iget(txsv->root->fs_info->sb,
//			&create_entry->file.location, txsv->root, NULL);
			original_location, txsv->root, NULL);
	if (IS_ERR(original_inode)) {
		BTRFS_SYM_DBG("INODE-GET > Error\n");
//		goto out_unlock;
		return PTR_ERR(original_inode);
	}

	new_inode_mode = original_inode->i_mode;

	inode = btrfs_new_inode(trans, snap->root, dir,
			name->name, name->len, dir->i_ino,
			entry->ino, BTRFS_I(dir)->block_group,
//			create_entry->mode, &index);
			new_inode_mode, &index);
	if (IS_ERR(inode)) {
		iput(original_inode);
		return PTR_ERR(inode);
	}

#if 0
	original_inode = btrfs_iget(txsv->root->fs_info->sb,
//			&create_entry->file.location, txsv->root, NULL);
			original_location, txsv->root, NULL);
	if (IS_ERR_OR_NULL(original_inode)) {
		BTRFS_SYM_DBG("INODE-GET > Error\n");
		goto out_unlock;
	}
#endif

	inode_set_bytes(inode, original_inode->i_bytes);
	btrfs_i_size_write(inode, original_inode->i_size);
	inode->i_ctime = original_inode->i_ctime;
	inode->i_mtime = original_inode->i_mtime;
	inode->i_atime = original_inode->i_atime;

	err = btrfs_init_inode_security(trans, inode, dir);
	if (err < 0) {
		drop_inode = 1;
		goto out_put_original_inode;
	}

	btrfs_update_inode(trans, snap->root, inode);

	btrfs_set_trans_block_group(trans, inode);

	err = btrfs_add_link(trans, dir, inode, name->name, name->len, 0, index);
	if (err)
		drop_inode = 1;
	else {
//		inode->i_mapping->a_ops = &btrfs_aops;
		btrfs_set_inode_aops(inode);
		btrfs_set_inode_extent_io_ops(inode);

		inode->i_mapping->backing_dev_info = &snap->root->fs_info->bdi;
//		inode->i_mapping->backing_dev_info = &root->fs_info->bdi;
//		BTRFS_I(inode)->io_tree.ops = &btrfs_extent_io_ops;

		inode->i_fop = &btrfs_acid_file_operations;
		inode->i_op = &btrfs_acid_file_inode_operations;
	}

	btrfs_update_inode_block_group(trans, inode);
	btrfs_update_inode_block_group(trans, dir);

out_put_original_inode:
	iput(original_inode);
out_unlock:
	if (drop_inode) {
		inode_dec_link_count(inode);
		goto out;
	}

//	original_ino = create_entry->ino;
	original_ino = entry->log_entry->ino;
	BTRFS_SYM_DBG("Taking care of extents for inode %llu -> %llu\n",
			original_ino, entry->ino);
	BTRFS_SYM_DBG("OBJECTID > snap root: %llu, txsv root: %llu\n",
			snap->root->root_key.objectid, txsv->root->root_key.objectid);

	err = -ENOMEM;
	path = btrfs_alloc_path();
	if (!path)
		goto out;

//	snap_path = btrfs_alloc_path();
//	if (!snap_path) {
//		btrfs_free_path(path);
//		goto out;
//	}

	err = btrfs_lookup_file_extent(NULL, txsv->root, path, original_ino, 0, 0);
	if (err < 0) {
		BTRFS_SYM_DBG("LOOKUP-FILE-EXTENT > Error\n");
		goto out;
	}

	while (1) {
		leaf = path->nodes[0];
		slot = path->slots[0];

		BTRFS_SYM_DBG("\tITEM > leaf: %p, slot: %d, leaf nritems: %d, bytenr: %llu\n",
				leaf, slot, btrfs_header_nritems(leaf), btrfs_header_bytenr(leaf));

		if (slot >= btrfs_header_nritems(leaf))
		{
			ret = btrfs_next_leaf(txsv->root, path);
			if (ret != 0) /* no more leafs. */
				break;

			leaf = path->nodes[0];
			slot = path->slots[0];
		}

//		btrfs_item_key(leaf, &disk_key, slot);
//		btrfs_disk_key_to_cpu(&item_key, &disk_key);
		btrfs_item_key_to_cpu(leaf, &item_key, slot);
		BTRFS_SYM_DBG("\tITEM FOUND > key: [%llu %d %llu]\n",
				item_key.objectid, item_key.type, item_key.offset);
		if (item_key.objectid > original_ino)
			break;

		if (item_key.objectid != original_ino)
			continue;

		if (item_key.type != BTRFS_EXTENT_DATA_KEY)
			continue;

		size = btrfs_item_size_nr(leaf, slot);
		buf = kzalloc(size, GFP_NOFS);
		if (!buf) {
			err = -ENOMEM;
			break;
		}

		BTRFS_SYM_DBG("\tEXTENT ITEM > size: %u\n", size);
		read_extent_buffer(leaf, buf, btrfs_item_ptr_offset(leaf, slot), size);
		item_type = le8_to_cpu(((struct btrfs_file_extent_item *) buf)->type);
		BTRFS_SYM_DBG("\tEXTENT ITEM > type: %d, ram: %llu\n",
				item_type,
				((struct btrfs_file_extent_item *) buf)->ram_bytes);

		snap_path = btrfs_alloc_path();
		if (!snap_path) {
			btrfs_free_path(path);
			goto out;
		}

		inner_trans = btrfs_start_transaction(snap->root, 1);
		BUG_ON(IS_ERR_OR_NULL(inner_trans));

		item_key.objectid = entry->ino;
		err = btrfs_insert_empty_item(inner_trans, snap->root,
				snap_path, &item_key, size);
		BUG_ON(err);

		write_extent_buffer(snap_path->nodes[0], buf,
				btrfs_item_ptr_offset(snap_path->nodes[0], snap_path->slots[0]),
				size);

		if ((item_type == BTRFS_FILE_EXTENT_REG)
				|| (item_type == BTRFS_FILE_EXTENT_PREALLOC)) {

			BTRFS_SYM_DBG("\tEXTENT ITEM > Increasing extent refs\n");
			ei = (struct btrfs_file_extent_item *) buf;
			item_bytenr = le64_to_cpu(ei->disk_bytenr);
			item_numbytes = le64_to_cpu(ei->disk_num_bytes);
			item_offset = le64_to_cpu(ei->offset);
			err = btrfs_inc_extent_ref(trans, snap->root,
					item_bytenr, item_numbytes, 0,
					snap->root->root_key.objectid,
					entry->ino,
					item_offset);
			if (err < 0) {
				BTRFS_SYM_DBG("\tEXTENT ITEM > Error increasing extent refs\n");
			}
		}

		btrfs_end_transaction(inner_trans, snap->root);
		btrfs_free_path(snap_path);


		kfree(buf);

		path->slots[0] ++;
	}

out_free_path:
	btrfs_free_path(path);
//	btrfs_free_path(snap_path);

out:
	iput(inode);
	return err;
}


static int __symexec_reconcile_mkdir(struct btrfs_trans_handle * trans,
//static int __symexec_reconcile_mkdir(
		struct btrfs_acid_snapshot * txsv,
		struct btrfs_acid_snapshot * snap, struct inode * dir,
		struct symexec_entry * entry)
{
//	struct btrfs_trans_handle * trans;
	struct btrfs_acid_log_mkdir * mkdir_entry;
	struct qstr * name;
	struct inode * inode;
	u64 index;
//	unsigned long trans_blocks_used;

	int err;

	if (!trans || !txsv || !snap || !dir || !entry)
		return -EINVAL;

	name = &entry->file->name;

	mkdir_entry = (struct btrfs_acid_log_mkdir *) entry->log_entry;

//	trans = btrfs_start_transaction(snap->root, 5);
//	if (IS_ERR(trans)) {
//		BTRFS_SYM_DBG("START-TRANS > Error\n");
//		err = PTR_ERR(trans);
////		break;
//		return err;
//	}
//	btrfs_set_trans_block_group(trans, dir);

	BTRFS_SYM_DBG("Creating Dir > name: %.*s, "
			"ino: %llu, dir: %lu, mode: %d\n",
			name->len, name->name,
			entry->ino, dir->i_ino, mkdir_entry->mode);

	inode = btrfs_new_inode(trans, snap->root, dir,
			name->name, name->len, dir->i_ino,
			entry->ino, BTRFS_I(dir)->block_group,
			(mkdir_entry->mode|S_IFDIR), &index);
	if (IS_ERR(inode)) {
		BTRFS_SYM_DBG("NEW-INODE > Error\n");
		return PTR_ERR(inode);
	}

	BTRFS_SYM_DBG("\tmode: %u, uid: %u, gid: %u\n",
			inode->i_mode, inode->i_uid, inode->i_gid);

	err = btrfs_init_inode_security(trans, inode, dir);
	if (err < 0)
		goto out_fail;
	BTRFS_SYM_DBG("\tAFTER SECURITY > mode: %u, uid: %u, gid: %u\n",
			inode->i_mode, inode->i_uid, inode->i_gid);

	inode->i_op = &btrfs_acid_dir_inode_operations;
	inode->i_fop = &btrfs_acid_dir_file_operations;
	btrfs_set_trans_block_group(trans, inode);

	btrfs_i_size_write(inode, 0);
	err = btrfs_update_inode(trans, snap->root, inode);
	if (err < 0)
		goto out_fail;

	err = btrfs_add_link(trans, dir, inode,
			name->name, name->len, 0, index);
	if (err < 0) {
		BTRFS_SYM_DBG("ADD-LINK > Error\n");
		goto out_fail;
	}

	btrfs_update_inode_block_group(trans, inode);
	btrfs_update_inode_block_group(trans, dir);

out_fail:
	iput(inode);
//	trans_blocks_used = trans->blocks_used;
//	btrfs_end_transaction_throttle(trans, snap->root);
//	btrfs_btree_balance_dirty(snap->root, trans_blocks_used);

	return err;
}

static struct page *
__symexec_reconcile_get_page(struct inode * inode, pgoff_t index)
{
	struct page * page = NULL;
	page = grab_cache_page(inode->i_mapping, index);
	if (!page)
		return NULL;

	if (!PageUptodate(page)) {
		btrfs_readpage(NULL, page);
		lock_page(page);
		if (!PageUptodate(page)) {
			unlock_page(page);
			page_cache_release(page);
			return NULL;
		}
	}
	wait_on_page_writeback(page);
	return page;
}

static int __symexec_reconcile_interval(struct inode * inode_from,
		struct inode * inode_to, pgoff_t first, pgoff_t last)
{
	struct btrfs_root * inode_to_root;
	u64 space_to_reserve;
	int nr_pages;
	struct page ** inode_from_pages, ** inode_to_pages;
	void * from_addr, * to_addr;
	u64 start_pos, num_bytes, end_of_last_block;
	u32 sectorsize;
	pgoff_t index;
	int ret = 0;
	int i;
	unsigned long int dirty_pages_cnt = 0;

	if (!inode_from || !inode_to)
		return -EINVAL;

	inode_to_root = BTRFS_I(inode_to)->root;

	ret = -ENOMEM;
	nr_pages = last - first + 1;
	inode_from_pages = kzalloc(sizeof(struct page *) * nr_pages, GFP_NOFS);
	if (!inode_from_pages)
		goto out;

	inode_to_pages = kzalloc(sizeof(struct page *) * nr_pages, GFP_NOFS);
	if (!inode_to_pages)
		goto free_txsv_pages;

	space_to_reserve = nr_pages << PAGE_CACHE_SHIFT;
	ret = btrfs_delalloc_reserve_space(inode_to, space_to_reserve);
	if (ret) {
		BTRFS_SUB_DBG(TX_RECONCILIATE, "Unable to reserve space !!\n");
		goto free_snap_pages;
	}

	for (index = first, i = 0; i < nr_pages; i ++, index ++) {
		inode_from_pages[i] = __symexec_reconcile_get_page(inode_from, index);
		if (!inode_from_pages[i]) {
			BTRFS_SUB_DBG(TX_RECONCILIATE,
					"\tInvalid txsv page index (%lu) or something\n", index);
			ret = -ENOMEM;
			break;
		}

		inode_to_pages[i] = __symexec_reconcile_get_page(inode_to, index);
		if (!inode_to_pages[i]) {
			BTRFS_SUB_DBG(TX_RECONCILIATE,
					"\tInvalid snap page index (%lu) or something\n", index);
//			unlock_page(txsv_page);
//			page_cache_release(txsv_page);
			ret = -ENOMEM;
			break;
		}

		from_addr = kmap(inode_from_pages[i]);
		to_addr = kmap(inode_to_pages[i]);
		memcpy(to_addr, from_addr, PAGE_CACHE_SIZE);
		kunmap(inode_from_pages[i]);
		kunmap(inode_to_pages[i]);
	}

	for (i = 0; i < nr_pages; i ++) {
		if (!inode_from_pages[i])
			continue;

//		kunmap(txsv_pages[index]);
		unlock_page(inode_from_pages[i]);
		page_cache_release(inode_from_pages[i]);
		inode_from_pages[i] = NULL;
	}

	if (ret < 0)
		goto err_pages;

//		kunmap(txsv_page);
//		unlock_page(txsv_page); /* this should be in a '__put_page()' */
//		page_cache_release(txsv_page);

//		start_pos = ((index << PAGE_CACHE_SHIFT) & ~(sectorsize - 1));
	start_pos = ((first << PAGE_CACHE_SHIFT)
			& ~(inode_to_root ->sectorsize - 1));
	num_bytes = space_to_reserve;
	end_of_last_block = (start_pos + num_bytes - 1);
	ret = btrfs_set_extent_delalloc(inode_to, start_pos,
			end_of_last_block, NULL);
	BUG_ON(ret);

err_pages:
	for (i = 0; i < nr_pages; i ++) {
		if (!inode_to_pages[i])
			continue;

		SetPageUptodate(inode_to_pages[i]);
		ClearPageChecked(inode_to_pages[i]);
		set_page_dirty(inode_to_pages[i]);

		unlock_page(inode_to_pages[i]);
		mark_page_accessed(inode_to_pages[i]);
		page_cache_release(inode_to_pages[i]);

		dirty_pages_cnt ++;
	}

	if (ret < 0) {
		btrfs_delalloc_release_space(inode_to, space_to_reserve);
		goto free_snap_pages;
	}
	balance_dirty_pages_ratelimited_nr(inode_to->i_mapping, dirty_pages_cnt);
	btrfs_throttle(inode_to_root);
	BTRFS_I(inode_to)->last_trans = inode_to_root->fs_info->generation + 1;
	btrfs_wait_ordered_range(inode_to, start_pos, space_to_reserve);


free_snap_pages:
	kfree(inode_to_pages);
free_txsv_pages:
	kfree(inode_from_pages);

out:
	return ret;
}

static int __symexec_reconcile_blocks(struct symexec_ctl * symexec,
		struct btrfs_acid_snapshot * txsv, struct btrfs_acid_snapshot * snap,
		struct symexec_list_tree_entry * lst_entry)
{
	struct btrfs_key txsv_key, snap_key;
	struct inode * snap_inode, * txsv_inode;
	struct symexec_entry * entry;
	struct btrfs_acid_log_rw * rw;

	struct rb_root pages_tree;
	struct rb_node * node;
	pgoff_t start, end;
	struct symexec_interval_entry * interval;
	struct symexec_interval_entry * best_interval;
	struct btrfs_fs_info * fs_info;
//	struct rb_node * to_erase;


	int err = 0;

	if (!symexec || !txsv || !snap || !lst_entry)
		return -EINVAL;

	pages_tree = RB_ROOT;

	fs_info = snap->root->fs_info;

	if (list_empty(&lst_entry->list)) {
		BTRFS_SYM_DBG("LIST IS EMPTY\n");
		return 0;
	}

	// this method should only be used when reconciling shared files
	// therefore, txsv_key.objectid == snap_key.objectid
//	txsv_key.objectid = lst_entry->ino;

//	entry = list_entry(&lst_entry->list.next, struct symexec_entry, list);
//	txsv_key.objectid = entry->log_entry->ino;
	txsv_key.objectid = lst_entry->ino;
	txsv_key.type = BTRFS_INODE_ITEM_KEY;
	txsv_key.offset = 0;
	
	snap_key.objectid = lst_entry->ino;
	snap_key.type = BTRFS_INODE_ITEM_KEY;
	snap_key.offset = 0;

//	err = __symexec_get_mapped(symexec, txsv_key.objectid,
//			&snap_key.objectid);
//	if (err < 0) {
//		BTRFS_SYM_DBG("GET-MAPPED-INODE > ino: %llu\n",
//				lst_entry->ino);
//		return err;
//	}

	BTRFS_SYM_DBG("RECONCILING BLOCKS FOR INODE (%llu -> %llu)\n", 
			txsv_key.objectid, snap_key.objectid);

	/* Populate the pages tree with the intervals from lst_entry.
	 * Each tree key will be the start offset, while its value should be
	 * the end offset.
	 */

	list_for_each_entry(entry, &lst_entry->list, list) {
		rw = (struct btrfs_acid_log_rw *) entry->log_entry;

		node = __tree_search(&pages_tree, rw->first_page);
		if (node) {
			interval = rb_entry(node, struct symexec_interval_entry, rb_node);
			if (interval->end < rw->last_page)
				interval->end = rw->last_page;
		} else {
			interval = kzalloc(sizeof(*interval), GFP_NOFS);
			interval->start = rw->first_page;
			interval->end = rw->last_page;
			__tree_insert(&pages_tree, interval->start, &interval->rb_node);
		}
	}

	BTRFS_SYM_DBG("BLOCKS TREE (BEFORE)\n");
	for (node = rb_first(&pages_tree); node; node = rb_next(node)) {
		interval = rb_entry(node, struct symexec_interval_entry, rb_node);
		BTRFS_SYM_DBG("s: %llu, end: %llu\n", interval->start, interval->end);
	}
	/* Populated. Now let us process the tree in order to get as few intervals
	 * as possible.
	 */
	best_interval = NULL;
	for (node = rb_first(&pages_tree); node; ) {
		interval = rb_entry(node, struct symexec_interval_entry, rb_node);
		if (!best_interval) {
			best_interval = interval;
			node = rb_next(node);
			continue;
		}

		if ((best_interval->end >= interval->start)
				|| ((best_interval->end - interval->start) >= -1)) {
			best_interval->end = max(best_interval->end, interval->end);
//			to_erase = node;
			node = rb_next(node);
			__tree_erase(&pages_tree, &interval->rb_node);
			kfree(interval);
		} else {
			best_interval = interval;
			node = rb_next(node);
		}
	}

	snap_inode = btrfs_iget(fs_info->sb, &snap_key, snap->root, NULL);
	if (IS_ERR_OR_NULL(snap_inode)) {
		BTRFS_SYM_DBG("SNAP-INODE-GET > inode: %p\n", snap_inode);
		return (IS_ERR(snap_inode) ? PTR_ERR(snap_inode) : -ENOENT);
	}

	txsv_inode = btrfs_iget(fs_info->sb, &txsv_key, txsv->root, NULL);
	if (IS_ERR_OR_NULL(txsv_inode)) {
		BTRFS_SYM_DBG("TXSV-INODE-GET > inode: %p\n", txsv_inode);
		return (IS_ERR(txsv_inode) ? PTR_ERR(txsv_inode) : -ENOENT);
	}

	BTRFS_SYM_DBG("BLOCKS TREE (AFTER)\n");

	for (node = rb_first(&pages_tree); node; node = rb_next(node)) {
		interval = rb_entry(node, struct symexec_interval_entry, rb_node);

		BTRFS_SYM_DBG("s: %llu, end: %llu\n", interval->start, interval->end);
		err = __symexec_reconcile_interval(txsv_inode, snap_inode,
				interval->start, interval->end);
		if (err < 0) {
			BTRFS_SYM_DBG("RECONCILE-INTERVAL > Error > s: %llu, e: %llu\n",
					interval->start, interval->end);
			break;
		}
	}

	iput(txsv_inode);
	iput(snap_inode);

//	iput(inode);

	return 0;
}

/**
 * __symexec_reconcile_trans_numitems - Returns the # items for the transaction.
 *
 * This solution isn't pretty, but we are tired and we barely have enough
 * imagination to write this description, let alone thing how to do this in
 * a simpler way. Sorry.
 */
static int __symexec_reconcile_trans_numitems(struct symexec_entry * entry)
{
	int items = 0;
	if (!entry)
		return -EINVAL;

	switch (entry->log_entry->type) {
	case BTRFS_ACID_LOG_CREATE:
	case BTRFS_ACID_LOG_MKDIR:
	case BTRFS_ACID_LOG_MKNOD:
	case BTRFS_ACID_LOG_SYMLINK:
		items = 5;
		break;
	case BTRFS_ACID_LOG_LINK:
		items = 3;
		break;
	case BTRFS_ACID_LOG_UNLINK:
	case BTRFS_ACID_LOG_RMDIR:
		items = 10;
		break;
	case BTRFS_ACID_LOG_RENAME:
		items = 20;
		break;
	}
	return items;
}

static int symexec_reconcile(struct symexec_ctl * symexec,
		struct btrfs_acid_snapshot * txsv, struct btrfs_acid_snapshot * snap)
{
	struct btrfs_fs_info * fs_info;
	struct rb_node * node;
	struct symexec_list_tree_entry * lst_entry;
	struct symexec_entry * entry;

	u64 dir_ino;
	u64 index;
	struct btrfs_key key;
	struct inode * dir;
	struct inode * inode;
	struct btrfs_acid_log_mkdir * mkdir_entry;
	struct btrfs_trans_handle * trans;
	unsigned long trans_blocks_used;
	struct dentry * dentry;

	int trans_num_items;

	int err = 0;

	if (!symexec || !txsv || !snap)
		return -EINVAL;

	fs_info = snap->root->fs_info;

#if 0
	list_for_each_entry(inode, &fs_info->sb->s_inodes, i_sb_list) {
		BTRFS_SYM_DBG("ACTIVE INODE > ino: %llu, location: %llu, root: %llu\n",
				inode->i_ino, BTRFS_I(inode)->location.objectid,
				BTRFS_I(inode)->root->root_key.objectid);
	}
#endif

	btrfs_start_delalloc_inodes(txsv->root, 0);
	btrfs_wait_ordered_extents(txsv->root, 0, 0);

	trans = btrfs_start_transaction(txsv->root, 0);
	if (IS_ERR(trans))
		return PTR_ERR(trans);
	btrfs_commit_transaction(trans, txsv->root);

	BTRFS_SYM_PRINT("RECONCILING LOG\n");

	list_for_each_entry(entry, &symexec->reconcile_log, reconcile_list) {
		key.objectid = entry->file->parent_location.objectid;
		key.type = BTRFS_INODE_ITEM_KEY;
		key.offset = 0;

		err = __symexec_get_mapped(symexec, key.objectid,
				&key.objectid);
		if (err < 0) {
			BTRFS_SYM_DBG("GET-MAPPED-PARENT > ino: %llu\n",
					entry->file->parent_location.objectid);
			return err;
		}

		BTRFS_SYM_DBG("RECONCILE > parent ino: %llu, mapped: %llu\n",
				key.objectid,
				entry->file->parent_location.objectid);

		dir = btrfs_iget(fs_info->sb, &key, snap->root, NULL);
		if (IS_ERR_OR_NULL(dir)) {
			BTRFS_SYM_DBG("INODE-GET > parent: %p\n", dir);
			return (IS_ERR(dir) ? PTR_ERR(dir) : -ENOENT);
		}

		trans_num_items = __symexec_reconcile_trans_numitems(entry);

		trans = btrfs_start_transaction(snap->root, trans_num_items);
		if (IS_ERR(trans)) {
			BTRFS_SYM_DBG("START-TRANS > Error\n");
			err = PTR_ERR(trans);
			break;
		}
		btrfs_set_trans_block_group(trans, dir);

		switch (entry->log_entry->type) {
		case BTRFS_ACID_LOG_CREATE:
			BTRFS_SYM_DBG("RECONCILE > CREATE p: %llu, i: %llu\n",
					dir->i_ino, entry->ino);
			err = __symexec_reconcile_create(trans, txsv, snap, dir, entry);
			break;
		case BTRFS_ACID_LOG_MKDIR:
			BTRFS_SYM_DBG("RECONCILE > MKDIR p: %llu, i: %llu\n",
					dir->i_ino, entry->ino);
			err = __symexec_reconcile_mkdir(trans, txsv, snap, dir, entry);
			break;
		case BTRFS_ACID_LOG_UNLINK:
			BTRFS_SYM_DBG("RECONCILE > UNLINK p: %llu, i: %llu\n",
					dir->i_ino, entry->ino);
			err = __symexec_reconcile_unlink(trans, txsv, snap, dir, entry);
			break;
		case BTRFS_ACID_LOG_LINK:
			BTRFS_SYM_DBG("RECONCILE > LINK p: %llu, i: %llu\n",
					dir->i_ino, entry->ino);
			err = __symexec_reconcile_link(trans, txsv, snap, dir, entry);
			break;
		case BTRFS_ACID_LOG_RENAME:
			BTRFS_SYM_DBG("RECONCILE > RENAME p: %llu, i: %llu\n",
					dir->i_ino, entry->ino);
			err = __symexec_reconcile_rename(trans, symexec, txsv, snap, dir, entry);
			break;
		case BTRFS_ACID_LOG_RMDIR:
			BTRFS_SYM_DBG("RECONCILE > RMDIR p: %llu, i: %llu\n",
					dir->i_ino, entry->ino);
			err = __symexec_reconcile_rmdir(trans, txsv, snap, dir, entry);
			break;
		case BTRFS_ACID_LOG_MKNOD:
			BTRFS_SYM_DBG("RECONCILE > MKNOD p: %llu, i: %llu\n",
					dir->i_ino, entry->ino);
			err = __symexec_reconcile_mknod(trans, txsv, snap, dir, entry);
			break;
		case BTRFS_ACID_LOG_SYMLINK:
			BTRFS_SYM_DBG("RECONCILE > SYMLINK p: %llu, i: %llu\n",
					dir->i_ino, entry->ino);
			err = __symexec_reconcile_create(trans, txsv, snap, dir, entry);
			break;
		}

		trans_blocks_used = trans->blocks_used;
		btrfs_end_transaction_throttle(trans, snap->root);
		btrfs_btree_balance_dirty(snap->root, trans_blocks_used);

		iput(dir);

		if (err < 0)
			break;
	}

	if (err < 0) {
		BTRFS_SYM_DBG("RECONCILE > Error\n");
		return err;
	}

	BTRFS_SYM_PRINT("RECONCILING BLOCKS\n");

	for (node = rb_first(&symexec->blocks); node; node = rb_next(node)) {
		lst_entry = rb_entry(node, struct symexec_list_tree_entry, rb_node);

		if (list_empty(&lst_entry->list)) {
			BTRFS_SYM_DBG("BLOCKS > ino: %llu EMPTY\n", lst_entry->ino);
			continue;
		}

		err = __symexec_reconcile_blocks(symexec, txsv, snap, lst_entry);

	}



#if 0
	BTRFS_SYM_PRINT("RECONCILING CREATIONS (Dir Tree)\n");

	for (node = rb_first(&symexec->dir); node; node = rb_next(node)) {
		lst_entry = rb_entry(node, struct symexec_list_tree_entry, rb_node);

		dir_ino = lst_entry->ino;
		parent_key.objectid = dir_ino;
		parent_key.type = BTRFS_INODE_ITEM_KEY;
		parent_key.offset = 0;

		dir = btrfs_iget(fs_info->sb, &parent_key, snap->root, NULL);
		if (IS_ERR_OR_NULL(dir)) {
			BTRFS_SYM_DBG("INODE-GET > parent: %p\n", dir);
			return (IS_ERR(dir) ? PTR_ERR(dir) : -ENOENT);
		}

		list_for_each_entry(entry, &lst_entry->list, list) {
			if (entry->origin != ORIGIN_GLOBAL)
				continue;

			trans_num_items = __symexec_reconcile_trans_numitems(entry);

			trans = btrfs_start_transaction(snap->root, trans_num_items);
			if (IS_ERR(trans)) {
				BTRFS_SYM_DBG("START-TRANS > Error\n");
				err = PTR_ERR(trans);
				break;
			}
			btrfs_set_trans_block_group(trans, dir);

			switch (entry->log_entry->type) {
			case BTRFS_ACID_LOG_CREATE:
				BTRFS_SYM_DBG("RECONCILE > CREATE p: %llu, i: %llu\n",
						dir->i_ino, entry->ino);
				err = __symexec_reconcile_create(trans, txsv, snap, dir, entry);
				break;
			case BTRFS_ACID_LOG_LINK:
				BTRFS_SYM_DBG("RECONCILE > LINK p: %llu, i: %llu\n",
						dir->i_ino, entry->ino);
				err = __symexec_reconcile_link(trans, txsv, snap, dir, entry);
				break;
			case BTRFS_ACID_LOG_MKDIR:
				BTRFS_SYM_DBG("RECONCILE > MKDIR p: %llu, i: %llu\n",
						dir->i_ino, entry->ino);
				err = __symexec_reconcile_mkdir(trans,
						txsv, snap, dir, entry);
				break;
			case BTRFS_ACID_LOG_MKNOD:
				BTRFS_SYM_DBG("RECONCILE > MKNOD p: %llu, i: %llu\n",
						dir->i_ino, entry->ino);
				err = __symexec_reconcile_mknod(trans, txsv, snap, dir, entry);
				break;
			case BTRFS_ACID_LOG_RENAME:
				BTRFS_SYM_DBG("RECONCILE > RENAME p: %llu, i: %llu\n",
						dir->i_ino, entry->ino);
				err = __symexec_reconcile_rename(trans, symexec,
						txsv, snap, dir, entry);
				break;
			case BTRFS_ACID_LOG_SYMLINK:
				BTRFS_SYM_DBG("RECONCILE > SYMLINK p: %llu, i: %llu\n",
						dir->i_ino, entry->ino);
				err = __symexec_reconcile_create(trans, txsv, snap, dir, entry);
				break;
			}
			trans_blocks_used = trans->blocks_used;
			btrfs_end_transaction_throttle(trans, snap->root);
			btrfs_btree_balance_dirty(snap->root, trans_blocks_used);
		}

		iput(dir);
		if (err < 0) {
			BTRFS_SYM_DBG("RECONCILE > Error\n");
			return err;
		}
	}

	BTRFS_SYM_PRINT("RECONCILED CREATIONS (Dir Tree)\n");

	BTRFS_SYM_PRINT("RECONCILING REMOVALS (REM Tree)\n");
	for (node = rb_first(&symexec->rem); node; node = rb_next(node)) {
		lst_entry = rb_entry(node, struct symexec_list_tree_entry, rb_node);

		list_for_each_entry(entry, &lst_entry->list, list) {
			if (entry->origin != ORIGIN_GLOBAL)
				continue;

			dir_ino = entry->file->parent_location.objectid;
			parent_key.objectid = dir_ino;
			parent_key.type = BTRFS_INODE_ITEM_KEY;
			parent_key.offset = 0;

			dir = btrfs_iget(fs_info->sb, &parent_key, snap->root, NULL);
			if (IS_ERR_OR_NULL(dir)) {
				BTRFS_SYM_DBG("INODE-GET > parent: %p\n", dir);
				return (IS_ERR(dir) ? PTR_ERR(dir) : -ENOENT);
			}

//			#if 0
			trans_num_items = __symexec_reconcile_trans_numitems(entry);

			trans = btrfs_start_transaction(snap->root, trans_num_items);
			if (IS_ERR(trans)) {
				BTRFS_SYM_DBG("START-TRANS > Error\n");
				err = PTR_ERR(trans);
				break;
			}
			btrfs_set_trans_block_group(trans, dir);
//#endif

			switch (entry->log_entry->type) {
			case BTRFS_ACID_LOG_UNLINK:
				BTRFS_SYM_DBG("RECONCILE > UNLINK p: %llu, i: %llu\n",
						dir->i_ino, entry->file->location.objectid);
				err = __symexec_reconcile_unlink(trans, txsv, snap, dir, entry);
				break;
			case BTRFS_ACID_LOG_RMDIR:
				BTRFS_SYM_DBG("RECONCILE > RMDIR p: %llu, i: %llu\n",
						dir->i_ino, entry->file->location.objectid);
				err = __symexec_reconcile_rmdir(trans, txsv, snap, dir, entry);
				break;
			}
			trans_blocks_used = trans->blocks_used;
			btrfs_end_transaction_throttle(trans, snap->root);
			btrfs_btree_balance_dirty(snap->root, trans_blocks_used);

			iput(dir);
		}

		if (err < 0) {
			BTRFS_SYM_DBG("RECONCILE > Error\n");
			return err;
		}
	}
#endif


	BTRFS_SYM_DBG("RECONCILE > Success!\n");

#if 0
	list_for_each_entry(inode, &fs_info->sb->s_inodes, i_sb_list) {
		BTRFS_SYM_DBG("ACTIVE INODE > ino: %llu, location: %llu, root: %llu\n",
				inode->i_ino, BTRFS_I(inode)->location.objectid,
				BTRFS_I(inode)->root->root_key.objectid);
	}
#endif

	return 0;
}

int btrfs_acid_reconcile(struct btrfs_acid_ctl * ctl,
		struct btrfs_acid_snapshot * txsv, struct btrfs_acid_snapshot * snap)
{
	struct symexec_ctl * symexec;
	struct btrfs_acid_snapshot_entry * entry;
	int snap_gen, txsv_gen;
	int err;

	if (!txsv || !snap)
		return -EINVAL;

	symexec = symexec_create(snap);
	if (IS_ERR(symexec)) {
		BTRFS_SYM_DBG("RECONCILE > error creating symexec ctl\n");
		return PTR_ERR(symexec);
	}

	snap_gen = atomic_read(&snap->gen);
	txsv_gen = atomic_read(&txsv->gen);

	BTRFS_SYM_DBG("RECONCILE > GENERATIONS > snap: %d, txsv: %d\n",
			snap_gen, txsv_gen);

	if (snap_gen == txsv_gen) {
		BTRFS_SYM_DBG("RECONCILE > Snap's gen == TxSv's gen: all OKAY\n");
		goto out;
	}

	if (list_empty(&ctl->historic_sv))
		goto apply_txsv;

	list_for_each_entry(entry, &ctl->historic_sv, list) {
		txsv_gen = atomic_read(&entry->snap->gen);
		if (txsv_gen <= snap_gen)
			continue;

		err = symexec_apply(symexec, &entry->snap->op_log);
		if (err < 0) {
			BTRFS_SYM_DBG("RECONCILE > error applying former txsv %.*s log\n",
					entry->snap->path.len, entry->snap->path.name);
			symexec_destroy(symexec);
			return err;
		}
	}

apply_txsv:
	err = symexec_apply(symexec, &txsv->op_log);
	if (err < 0) {
		BTRFS_SYM_DBG("RECONCILE > error applying txsv's log\n");
		symexec_destroy(symexec);
		return err;
	}

	err = symexec_validate(symexec, snap);
	if (err < 0) {
		BTRFS_SYM_DBG("RECONCILE > error validating snapshot\n");
		return err;
	}

	symexec_print_dir_tree(symexec);
	symexec_print_rem_tree(symexec);
	symexec_print_blocks_tree(symexec);
	symexec_print_dirty_dirs_tree(symexec);
	symexec_print_reconcile_log(symexec);

	err = symexec_reconcile(symexec, txsv, snap);

out:
	symexec_destroy(symexec);
	return 0;
}

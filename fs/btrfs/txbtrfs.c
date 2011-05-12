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
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/kernel.h>
#include <linux/radix-tree.h>
#include <linux/namei.h>
#include <linux/fsnotify.h>
#include <linux/list.h>
#include "ctree.h"
#include "btrfs_inode.h"
#include "transaction.h"
#include "disk-io.h"
#include "txbtrfs.h"
#include "txbtrfs-log.h"
#include "txbtrfs-misc.h"
#include "hash.h"
#include "xattr.h"

struct snapshot_list
{
	struct btrfs_acid_snapshot * snap;
	struct list_head list;
};



/*
 * TxBtrfs aims at introducing Transactional Semantics into the file
 * system, using Btrfs as its coding base. (to be expanded)
 */

static struct btrfs_acid_snapshot *
__snapshot_read_leaf(struct extent_buffer * leaf,
		struct btrfs_acid_snapshot_item * si);
static int __snapshot_destroy(struct btrfs_acid_snapshot * snap);
static int __snapshot_set_perms(struct inode * dir, struct dentry * dentry);
static struct dentry *
__snapshot_instantiate_dentry(struct dentry * dentry);
static struct btrfs_acid_snapshot *
__snapshot_add(struct btrfs_root * root, struct qstr * path);
static int __snapshot_remove_pid(struct btrfs_acid_ctl * ctl, pid_t pid);
static int __snapshot_remove(struct btrfs_acid_ctl * ctl);
static int __snapshot_create_path(struct btrfs_acid_ctl * ctl,
		struct qstr * path, pid_t pid);
static void __snapshot_destroy_path(struct qstr * path);

int btrfs_acid_destroy_snapshot(struct btrfs_acid_snapshot * snap,
		struct btrfs_fs_info * fs_info);
static int btrfs_has_acid_ancestor(struct btrfs_acid_ctl * ctl,
		struct task_struct * task);


/* Copy the contents of 'src' and return them in newly allocated memory.
 */
struct btrfs_key * btrfs_acid_copy_key(struct btrfs_key * src)
{
	struct btrfs_key * key;

	if (!src)
		return ERR_PTR(-EINVAL);
	key = kzalloc(sizeof(*key), GFP_NOFS);
	if (!key)
		return ERR_PTR(-ENOMEM);
	memcpy(key, src, sizeof(*key));

	return key;
}

static inline void print_key(struct btrfs_key * key)
{
	printk(KERN_DEBUG "key [%llu %d %llu]\n",
			key->objectid, key->type, key->offset);
}

static inline int __cmp_roots(struct btrfs_root * r1, struct btrfs_root * r2)
{
	return (r1 && r2
			&& (r1->root_key.objectid == r2->root_key.objectid)
			&& (r1->root_key.type == r2->root_key.type)
			&& (r1->root_key.offset == r2->root_key.offset));
}


/* based on btrfs_inode_by_name */
static int change_tree_root_ref_name(struct btrfs_trans_handle * trans,
		struct btrfs_root * root, u64 objectid, u8 type, u64 offset,
		char * name, int name_len)
{
	int ret = 0;
	struct btrfs_key search_key;
	struct btrfs_path * path;
	struct extent_buffer * leaf;
	struct btrfs_root_ref * ref;
	char ref_name[BTRFS_NAME_LEN];
	int ref_name_len;

	search_key.objectid = objectid;
	search_key.type = type;
	search_key.offset = offset;

	path = btrfs_alloc_path();
	ret = btrfs_search_slot(trans, root,
			&search_key, path, 0, 1);
	BUG_ON(ret < 0);
	if (ret != 0)
	{
		ret = -ENOENT;
		goto err_free_path;
	}

	leaf = path->nodes[0];
	ref = btrfs_item_ptr(leaf, path->slots[0], struct btrfs_root_ref);
	ref_name_len = btrfs_root_ref_name_len(leaf, ref);
	if (ref_name_len <= 0)
	{
		BTRFS_SUB_DBG(FS, "Change root: ref name len <= 0\n");
		ref_name[0] = '\0';
	} else
		read_extent_buffer(leaf, ref_name,
				(unsigned long) (ref+1), ref_name_len);


	BTRFS_SUB_DBG(FS, "Change root: ref: dirid = %llu, sequence = %llu, "
			"name = %.*s, namelen = %d\n",
			btrfs_root_ref_dirid(leaf, ref),
			btrfs_root_ref_sequence(leaf, ref),
			ref_name_len, ref_name, ref_name_len);

	if (ref_name_len + 4 < BTRFS_NAME_LEN)
	{
		BTRFS_SUB_DBG(FS, "Change root: new_name = %s, new_name_len = %d\n",
				name, name_len);
		write_extent_buffer(leaf, name, (unsigned long) (ref+1), name_len);
		btrfs_set_root_ref_name_len(leaf, ref, name_len);
		btrfs_mark_buffer_dirty(leaf);
	}

err_free_path:
	btrfs_free_path(path);


	return ret;
}

static int get_fs_root_dir_item(struct btrfs_trans_handle * trans,
		struct file * to_find)
{
	struct dentry * to_find_dentry = fdentry(to_find);
	struct dentry * parent = dget_parent(to_find_dentry);
	struct btrfs_path * path;
	struct btrfs_dir_item * dir_item;
	struct btrfs_root * root = BTRFS_I(to_find_dentry->d_inode)->root;
	struct extent_buffer * leaf;
	struct btrfs_key key;
	int name_len;
	char * name;

	path = btrfs_alloc_path();

	dir_item = btrfs_lookup_dir_item(trans, root->fs_info->fs_root, path,
			parent->d_inode->i_ino,	to_find_dentry->d_name.name,
			to_find_dentry->d_name.len, 0);

	BUG_ON(! dir_item || IS_ERR(dir_item));

	leaf = path->nodes[0];
	btrfs_dir_item_key_to_cpu(leaf, dir_item, &key);

	name_len = btrfs_dir_name_len(leaf, dir_item);
	name = (char *) kzalloc(sizeof(*name) * name_len, GFP_KERNEL);

	read_extent_buffer(leaf, name, (unsigned long) (dir_item+1), name_len);


	BTRFS_SUB_DBG(FS, "Dir item: location key = [%llu %d %llu], name = %.*s\n",
			key.objectid, key.type, key.offset, name_len, name);

	kfree(name);
	btrfs_free_path(path);


	return 0;
}

static struct btrfs_root * get_root_by_name(struct btrfs_inode * inode,
		struct qstr * name)
{
	struct btrfs_root * objective = NULL;
	struct btrfs_dir_item *di;
	struct btrfs_path *path;
	struct btrfs_root * root = inode->root;
	struct btrfs_key location;

	path = btrfs_alloc_path();
	BUG_ON(!path);

	di = btrfs_lookup_dir_item(NULL, root, path, inode->vfs_inode.i_ino,
			name->name, name->len, 0);
	if (!di || IS_ERR(di))
	{
		BTRFS_SUB_DBG(FS, "(get_root_by_name) dir item is NULL or ERR: %llx\n",
				(unsigned long long) di);
		goto out;
	}

	btrfs_dir_item_key_to_cpu(path->nodes[0], di, &location);
	btrfs_free_path(path);

	objective = btrfs_lookup_fs_root(root->fs_info, location.objectid);

out:
	return objective;
}

static struct btrfs_acid_snapshot * fill_acid_txsv(struct btrfs_root * sv,
		struct btrfs_key * key, unsigned long parent_ino,
		char * name, int name_len)
{
	struct btrfs_acid_snapshot * snap;

	if (!sv || !key || !name || (name_len <= 0))
		return ERR_PTR(-EINVAL);

	snap = kzalloc(sizeof(*snap), GFP_NOFS);
	if (!snap)
		return ERR_PTR(-ENOMEM);

	snap->path.name = kzalloc(sizeof(char) * name_len, GFP_NOFS);
	if (!snap->path.name)
	{
		kfree(snap);
		return ERR_PTR(-ENOMEM);
	}

	snap->root = sv;
	snap->gen = sv->root_item.generation;
	snap->location = key;
	snap->parent_ino = parent_ino;
	snap->path.len = name_len;
	snap->path.hash = full_name_hash(name, name_len);
	snap->hash = btrfs_name_hash(name, name_len);

	memcpy(snap->path.name, name, name_len);

	return snap;
}


static struct btrfs_acid_snapshot *
find_acid_subvol(struct btrfs_root * tree_root)
{
	int ret = 0;
	struct btrfs_root * sv = NULL;
	struct btrfs_path * path;
	struct btrfs_key location;
	struct btrfs_key found_key;
	struct btrfs_disk_key disk_key;
	struct extent_buffer * leaf;

	struct btrfs_acid_tx_subvol_item * ti;
	struct btrfs_disk_key txsv_disk_key;
	struct btrfs_key txsv_key;
	unsigned long txsv_parent_ino;
	int txsv_name_len;
	char * txsv_name;

	struct btrfs_acid_snapshot * txsv = NULL;

	int slot;

	/* search based on 'debug-tree.c' from 'btrfs-progs-unstable'. */

	location.objectid = 0;
	location.offset = 0;
//	btrfs_set_key_type(&location, BTRFS_ROOT_ITEM_KEY);
	btrfs_set_key_type(&location, BTRFS_ACID_TX_SUBVOL_ITEM_KEY);

	path = btrfs_alloc_path();
	if (!path)
		return ERR_PTR(-ENOMEM);

	/* As we are running in the very beginning, before the FS is even mounted,
	 * we shouldn't be concerned with parallel accesses to the tree. Also, if
	 * we keep locks, once we call 'btrfs_read_fs_root_no_name' we will hang.
	 * If we ever find another way to release the locks before calling that
	 * method, this should be discarded.
	 */
	path->skip_locking = 1;

	ret = btrfs_search_slot(NULL, tree_root, &location, path, 0, 0);
	BUG_ON(ret < 0); /* wtf happened? */
	/* Against all we expected, 'ret' can be 1 even if there are items in the
	 * leaves. Go figure... */

	/* basic idea, loop until one of two things happens:
	 * 	1) 'btrfs_next_leaf' returns something different than zero, meaning we
	 *  have no more leaves that match our criteria; or
	 *  2) we find a transactional subvolume.
	 */
	while (1)
	{
		leaf = path->nodes[0];
		slot = path->slots[0];

		if (slot >= btrfs_header_nritems(leaf))
		{
			ret = btrfs_next_leaf(tree_root, path);
			if (ret != 0) /* no more leafs. */
				break;

			leaf = path->nodes[0];
			slot = path->slots[0];
		}

		btrfs_item_key(leaf, &disk_key, slot);
		btrfs_disk_key_to_cpu(&found_key, &disk_key);

		if (btrfs_key_type(&found_key) != BTRFS_ACID_TX_SUBVOL_ITEM_KEY)
			goto loop_again;

		BTRFS_SUB_DBG(TX, "Found tx subvol item: [%llu %d %llu]\n",
				found_key.objectid, found_key.type, found_key.offset);

		ti = btrfs_item_ptr(leaf, slot, struct btrfs_acid_tx_subvol_item);
		if (IS_ERR_OR_NULL(ti))
		{
			// TODO: handle error condition.
			BUG();
		}

		btrfs_tx_subvol_key(leaf, ti, &txsv_disk_key);
		btrfs_disk_key_to_cpu(&txsv_key, &txsv_disk_key);
		txsv_name_len = btrfs_tx_subvol_name_len(leaf, ti);
		txsv_parent_ino = btrfs_tx_subvol_parent_dirid(leaf, ti);

		txsv_name = kzalloc(sizeof(char) * txsv_name_len, GFP_NOFS);
		BUG_ON(!txsv_name);
		read_extent_buffer(leaf, txsv_name, (unsigned long)(ti + 1),
					txsv_name_len);

		BTRFS_SUB_DBG(TX, "Tx Subvol root key: [%llu %d %llu], name: %.*s, "
				"parent inode: %lu\n",
				txsv_key.objectid, txsv_key.type, txsv_key.offset,
				txsv_name_len, txsv_name,
				txsv_parent_ino);


		/* This key matches a transactional subvolume. Let's get its root. */
		sv = btrfs_read_fs_root_no_name(tree_root->fs_info, &txsv_key);
		if (sv) /* found it. break and live happily ever after. */
			break;

		/* something happened, let's keep trying. */
loop_again:
		path->slots[0] ++;
	}
	btrfs_free_path(path);

	if (sv)
	{
		txsv = fill_acid_txsv(sv, &txsv_key, txsv_parent_ino,
				txsv_name, txsv_name_len);
		if (IS_ERR_OR_NULL(txsv))
			goto out;

		BTRFS_SUB_DBG(TX, "Last key found is a Transactional Subvolume.\n");
		BTRFS_SUB_DBG(TX, "TXSV: root %p key [%llu %d %llu] gen %llu\n",
				txsv->root, txsv->location->objectid, txsv->location->type,
				txsv->location->offset, (unsigned long long) txsv->gen);
		BTRFS_SUB_DBG(TX, "TXSV: parent ino: %lu name: %.*s\n",
				txsv->parent_ino, txsv->path.len, txsv->path.name);

	}
	else
		BTRFS_SUB_DBG(TX, "No Transactional Subvolume found.\n");

out:
	return txsv;
}


int btrfs_is_acid_subvol(struct btrfs_root * root)
{
	struct btrfs_acid_ctl * ctl;
	u64 flags;
	int ret = 0;

	if (!root)
		/* we should return an error, but this is a 'true' or 'false' kind
		 * of method, so just return false and hope for the best. */
		return 0;

	ctl = &root->fs_info->acid_ctl;
	down_read(&ctl->sv_sem);
	if (!ctl->sv)
		goto out_up_sv;

	/* We have a TX Subvol, so 'root' still might be a TX SV root after all.
	 * Let us check for the right flags in its root, just to make sure.
	 * The semaphore is acquired to make sure no one changes the root's flags,
	 * or delete it. */
	down_read(&root->fs_info->subvol_sem);
	flags = btrfs_root_flags(&root->root_item);
	up_read(&root->fs_info->subvol_sem);
	BTRFS_SUB_DBG(TX, "Subvolume flags = %llu\n", flags);
	if (!(flags & BTRFS_ROOT_SUBVOL_ACID))
		goto out_up_sv;

	/* The root is marked as a transactional subvolume, but we still should
	 * check if it is our TXSV --- yes, we may allow changing between
	 * transactional subvolumes in the future, or something like that.
	 */
	ret = __cmp_roots(ctl->sv->root, root);

out_up_sv:
	up_read(&ctl->sv_sem);
	return ret;
}

int btrfs_is_acid_inode(struct inode * inode)
{
	struct btrfs_inode * our;
	if (!inode)
		return 0;

	our = BTRFS_I(inode);
	return (our->root->snap != NULL);
}

int btrfs_acid_allow(struct inode * inode)
{
	struct btrfs_acid_snapshot * snap;
	struct btrfs_inode * our;

	if (!inode)
		return -EINVAL;

	our = BTRFS_I(inode);
	if (!our->root->snap)
		return -EINVAL;

	if (current->pid != our->root->snap->owner_pid)
		return -ENOENT;

	return 0;
}

/* Finds the first transactional ancestor of the current task and returns its
 * associated snapshot. If 'found_pid' is not-NULL, and if a snapshot is found,
 * assigns the ancestor's pid to 'found_pid'.
 * If this method returns NULL, then 'found_pid' is set to -1.
 *
 * This method may return the very same pid in 'found_pid' as the current's.
 */
struct btrfs_acid_snapshot *
btrfs_acid_find_valid_ancestor(struct btrfs_acid_ctl * ctl,
		struct task_struct * task, pid_t * found_pid)
{
	struct btrfs_acid_snapshot * snap = NULL;

	if (!ctl || !task)
		goto out;

	BTRFS_SUB_DBG(TX, "current task pid = %d\n", task->pid);
	down_read(&ctl->curr_snaps_sem);
	while (task && !is_global_init(task)) {
		BTRFS_SUB_DBG(TX, "\ttask pid = %d\n", task->pid);
		snap = radix_tree_lookup(&ctl->current_snapshots, task->pid);
		if (snap) {
			if (found_pid)
				*found_pid = task->pid;
			break;
		}
		task = task->parent;
	}
	up_read(&ctl->curr_snaps_sem);

out:
	if (!snap && found_pid)
		*found_pid = -1;

	return snap;
}

static int btrfs_has_acid_ancestor(struct btrfs_acid_ctl * ctl,
		struct task_struct * task)
{
	return (btrfs_acid_find_valid_ancestor(ctl, task, NULL) ? 1 : 0);
}

/* Checks if the current process is in a transactional scope, and one of the
 * following scenarios may happen:
 *
 * 1) it is in fact the process that started the transaction;
 * 2) it is a child of the process that started the transaction, or one of the
 * current process' ancestors is;
 * 3) it is not on a transactional scope, and we should return NULL.
 */
static struct btrfs_acid_snapshot *
__check_transactional_process(struct btrfs_acid_ctl * ctl)
{
	struct task_struct * task;
	struct btrfs_acid_snapshot * snap;
	struct btrfs_acid_snapshot_pid * pid_entry;
	int mapping = 0;
	pid_t found_pid = 0;

	if (!ctl)
		return ERR_PTR(-EINVAL);

	BTRFS_SUB_DBG(TX, "checking PID = %d\n", current->pid);

	/*down_read(&ctl->curr_snaps_sem);
	task = get_current();
	while (!is_global_init(task)) {
		BTRFS_SUB_DBG(TX, "* task pid = %d\n", task->pid);
		snap = radix_tree_lookup(&ctl->current_snapshots, task->pid);
		if (snap) {
			found_pid = task->pid;
			break;
		}
		task = task->parent;
	}
	up_read(&ctl->curr_snaps_sem);*/
	snap = btrfs_acid_find_valid_ancestor(ctl, get_current(), &found_pid);
	BTRFS_SUB_DBG(TX, "snap = %p\n", snap);

	if (!snap)
		return NULL;

	down_write(&ctl->curr_snaps_sem);
	down_write(&snap->known_pids_sem);
	task = get_current();
	while (is_global_init(task) || (task->pid != found_pid)) {
		radix_tree_insert(&ctl->current_snapshots, task->pid, (void *) snap);

		pid_entry = kzalloc(sizeof(*pid_entry), GFP_NOFS);
		BUG_ON(!pid_entry);
		pid_entry->pid = task->pid;
		list_add(&pid_entry->list, &snap->known_pids);

		task = task->parent;
	}
	up_write(&snap->known_pids_sem);
	up_write(&ctl->curr_snaps_sem);

	return snap;
}

int btrfs_acid_d_hash(struct dentry * dentry, struct qstr * str)
{
	struct inode * inode = dentry->d_inode;
	struct btrfs_inode * our_inode = BTRFS_I(inode);
	struct btrfs_root * root = our_inode->root;
	struct btrfs_acid_ctl * ctl = &root->fs_info->acid_ctl;
	struct btrfs_acid_snapshot * snap = NULL;

	/* At this point we should be in one of the following conditions:
	 * 	1) The access isn't to a TXSV and we should simply return, or
	 * 	2) Parent is not a TXSV but 'str' is a TXSV and we should deal with
	 * 	it accordingly, or
	 * 	3) Parent is a TX Snapshot and we should simply return.
	 */

	BTRFS_SUB_DBG(FS, "dentry name: %.*s, str: %.*s\n",
			dentry->d_name.len, dentry->d_name.name,
			str->len, str->name);

	down_read(&ctl->sv_sem);
	if (!ctl->sv) /* No TXSV, nothing to do. */
		goto ctl_up_read;

	BTRFS_SUB_DBG(FS, "str hash: %d, TXSV hash: %d\n",
			str->hash, ctl->sv->path.hash);

	if (ctl->sv->path.hash != str->hash)
		goto ctl_up_read; /* We are not looking for TXSV, therefore return. */

	BTRFS_SUB_DBG(FS, "Same name as TXSV\n");

	if (inode->i_ino != ctl->sv->parent_ino)
		goto ctl_up_read; /* Same name, different parent. Not the TXSV. */

	BTRFS_SUB_DBG(FS, "Same parent as TXSV\n");

	/* We are trying to access the TXSV, therefore let's find the current
	 * process' snapshot and map the access there. */
//	down_read(&ctl->curr_snaps_sem);
//	snap = radix_tree_lookup(&ctl->current_snapshots, current->pid);
//	up_read(&ctl->curr_snaps_sem);
	snap = __check_transactional_process(ctl);
	if (!snap)
	{
		BTRFS_SUB_DBG(TX, "No Snapshot found for PID = %d\n", current->pid);
		goto ctl_up_read;
	}

	/* We've got the snapshot. Map the bastard. */
	str->name = kzalloc(snap->path.len, GFP_NOFS);
	BUG_ON(!str->name);
	memcpy((void *) str->name, (void *) snap->path.name, snap->path.len);
	str->len = snap->path.len;
	str->hash = snap->path.hash;

	BTRFS_SUB_DBG(TX, "Mapped PID = %d to SNAP = %.*s\n",
			current->pid, str->len, str->name);

ctl_up_read:
	up_read(&ctl->sv_sem);
	return 0;
}

int btrfs_acid_d_revalidate(struct dentry * dentry, struct nameidata * nd)
{
	struct btrfs_root * root;
	struct btrfs_acid_ctl * ctl;

//	BTRFS_TX_DBG("REVALIDATE", "Here we are.\n");
	if (!dentry)
		goto out;
//	BTRFS_TX_DBG("REVALIDATE", "Here we are #2.\n");

	if (!dentry->d_inode)
	{
		BTRFS_SUB_DBG(FS, "dentry->d_inode == NULL\n");
		goto out;
	}
//	BTRFS_TX_DBG("REVALIDATE", "Here we are. #3\n");

	if (!BTRFS_I(dentry->d_inode)->root)
	{
		BTRFS_SUB_DBG(FS, "dentry->d_inode->root == NULL\n");
		goto out;
	}
//	BTRFS_TX_DBG("REVALIDATE", "Here we are. #4\n");

	root = BTRFS_I(dentry->d_inode)->root;

	if (!root->fs_info)
	{
		BTRFS_SUB_DBG(FS, "root->fs_info == NULL\n");
		goto out;
	}
//	BTRFS_TX_DBG("REVALIDATE", "Here we are. #5\n");

	ctl = &root->fs_info->acid_ctl;

	BTRFS_SUB_DBG(FS, "name: %.*s\n",
			dentry->d_name.len, dentry->d_name.name);

	down_read(&ctl->sv_sem);
	if (!ctl->sv)
		goto out_up_read; /* No TXSV, nothing to do. */

	if (ctl->sv->path.hash == dentry->d_name.hash)
	{
		/* Same hash. */
		if (ctl->sv->parent_ino == dentry->d_parent->d_inode->i_ino)
		{
			/* Same parent. */
			d_drop(dentry);
			BTRFS_SUB_DBG(FS, "Dropped it.\n");
		}
	}

out_up_read:
	up_read(&ctl->sv_sem);

out:
	return 0;
}


int btrfs_acid_tx_start(struct file * file)
{
	int ret = 0;
	struct dentry * sv_dentry;
	struct btrfs_root * root;
	struct btrfs_acid_snapshot * snap = NULL;
	pid_t curr_pid = current->pid;

	sv_dentry = dget(fdentry(file));

	BTRFS_SUB_DBG(TX, "Starting transaction on %.*s for process %d\n",
			sv_dentry->d_name.len, sv_dentry->d_name.name, curr_pid);

	/* First of all, we must check if 'sv_dentry' actually is a valid
	 * transactional subvolume. Not only it must have the right flags, it must
	 * be the one set as the TX SV in fs_info's acid_ctl.
	 */
	/* We may have an additional scenario: the current root may be a snapshot
	 * we are trying to start a transaction on. This may happen if a child
	 * process nests a 'start transaction' within the parent's running
	 * transaction. Instead of creating a new transaction, we will follow the
	 * 'flat transaction' model, in which every nested transaction is seen
	 * as part of the transaction it is nested within.
	 */
	root = BTRFS_I(sv_dentry->d_inode)->root;

	/* check if we have a transactional parent.
	 * If not, return -ENOPERM; otherwise, return success. */
	if (root->snap) {
		if (!btrfs_has_acid_ancestor(&root->fs_info->acid_ctl, get_current()))
			ret = -ENOPERM;
		goto out;
	}

	if (!btrfs_is_acid_subvol(root))
	{
		ret = -EINVAL;
		goto out;
	}

	/* Okay, we are accessing a TXSV. Next step: create a snapshot for our
	 * process, before we can go any further.
	 */
	snap = btrfs_acid_create_snapshot(sv_dentry);
	if (IS_ERR(snap))
	{
		ret = PTR_ERR(snap);
		goto out;
	}

	BTRFS_SUB_DBG(TX, "Transaction %d mapped onto %.*s\n",
			snap->owner_pid, snap->path.len, snap->path.name);

	/* The snapshot is created, added to the tree, everything is either
	 * fine or not. Anyway, we have nothing else to do, so we return. */

out:
	dput(sv_dentry);
	return ret;
}

int btrfs_acid_tx_commit(struct file * file)
{
	int ret = 0;
	struct dentry * sv_dentry;
	struct btrfs_root * root;
	struct btrfs_acid_snapshot * snap = NULL;
	struct btrfs_acid_ctl * ctl;
	struct btrfs_fs_info * fs_info;
	pid_t curr_pid = current->pid;

	struct btrfs_acid_log_entry * entry;
	struct list_head * head;

	if (!file)
	{
		BTRFS_SUB_DBG(COMMIT, "file == NULL\n");
		return -EINVAL;
	}

	sv_dentry = dget(fdentry(file));
	root = BTRFS_I(sv_dentry->d_inode)->root;

	/* If we are to commit, we must be working inside our own snapshot.
	 * Therefore, we must check if the root we have is the root of a snapshot.
	 * If so, we are ok; otherwise, we won't support this operation.
	 */
	if (!root->snap)
	{
		BTRFS_SUB_DBG(COMMIT, "Not a snapshot.\n");
		ret = -ENOTSUPP;
		goto out;
	}

	fs_info = root->fs_info;
	ctl = &fs_info->acid_ctl;

	down_read(&ctl->curr_snaps_sem);
	snap = radix_tree_lookup(&ctl->current_snapshots, current->pid);
	up_read(&ctl->curr_snaps_sem);
	if (!snap)
	{
		BTRFS_SUB_DBG(COMMIT, "No Snapshot found for PID = %d\n", current->pid);
		ret = -ENOTSUPP;
		goto out;
	}

	/* Print the read-set log */
	head = &snap->read_log;
	BTRFS_SUB_DBG(COMMIT, "--------- READ SET ----------\n");
	list_for_each_entry(entry, head, list) {
		BTRFS_SUB_DBG(COMMIT, "clock %d, type %d, size: %d, "
				"location [%llu %d %llu]\n",
				entry->clock, entry->type, entry->size,
				entry->location.objectid, entry->location.type,
				entry->location.offset);

		if (entry->type == BTRFS_ACID_LOG_READ) {
			BTRFS_SUB_DBG(COMMIT, "\tfirst: %d, last: %d\n",
				((struct btrfs_acid_log_entry_rw *) entry->data)->first_page,
				((struct btrfs_acid_log_entry_rw *) entry->data)->last_page);
		}
	}

	/* Print the write-set log */
	head = &snap->write_log;
	BTRFS_SUB_DBG(COMMIT, "--------- WRITE SET ----------\n");
	list_for_each_entry(entry, head, list) {
		BTRFS_SUB_DBG(COMMIT, "clock %d, type %d, size: %d, "
				"location [%llu %d %llu]\n",
				entry->clock, entry->type, entry->size,
				entry->location.objectid, entry->location.type,
				entry->location.offset);

		if (entry->type == BTRFS_ACID_LOG_WRITE) {
			BTRFS_SUB_DBG(COMMIT, "\tfirst: %d, last: %d\n",
				((struct btrfs_acid_log_entry_rw *) entry->data)->first_page,
				((struct btrfs_acid_log_entry_rw *) entry->data)->last_page);
		}
	}

out:
	dput(sv_dentry);

	/* NOTE:
	 * This hangs the kernel. We shall take it as a fight for another day. */
/*	if (ret >= 0) {
		ret = btrfs_acid_destroy_snapshot(snap, fs_info);
		if (ret < 0) {
			BTRFS_SUB_DBG(COMMIT, "Error destroying snapshot\n");
		}
	}*/

	return ret;
}

/**
 * btrfs_acid_change_root -- From the perspective of the file system, one
 * given root is suddenly associated with a different key, pointing to a
 * different root node.
 *
 * (further description pending implementation decisions)
 */
int btrfs_acid_change_root(struct file * file,
		struct btrfs_ioctl_acid_change_root_args * args)
{
	int ret = 0;
	struct file * from_file, * to_file;
	struct dentry * from_dentry, * to_dentry;
	char * from_name, * to_name;
	char * new_name;
	int from_name_len, new_name_len;
	struct btrfs_inode * from_inode, * to_inode;
	struct btrfs_root * from_root, * to_root;
	struct btrfs_key * from_location, * to_location;
	struct btrfs_key * from_root_key, * to_root_key;
	struct btrfs_trans_handle * trans;

	BTRFS_SUB_DBG(TX, "Change root: fd = %lld to fd = %lld\n",
			args->from_fd, args->to_fd);

	from_file = fget(args->from_fd);
	to_file = fget(args->to_fd);

	from_dentry = from_file->f_path.dentry;
	to_dentry = to_file->f_path.dentry;

	from_name =
			kzalloc(sizeof(*from_name) * from_dentry->d_name.len, GFP_KERNEL);
	if (!from_name)
	{
		ret = -ENOMEM;
		goto err_fput;
	}

	to_name = kzalloc(sizeof(*to_name) * to_dentry->d_name.len, GFP_KERNEL);
	if (!to_name)
	{
		ret = -ENOMEM;
		goto err_free_from_name;
	}

	memcpy(from_name, from_dentry->d_name.name, from_dentry->d_name.len);
	memcpy(to_name, to_dentry->d_name.name, to_dentry->d_name.len);

	from_name_len = from_dentry->d_name.len;
	new_name_len = from_name_len + 4;
	new_name = (char *) kzalloc(new_name_len+1, GFP_KERNEL);
	memcpy(new_name, from_name, from_name_len);
	memcpy(new_name+from_name_len, "_new", 4);

	BTRFS_SUB_DBG(TX, "Change root: '%s' to '%.*s'\n", from_name,
			new_name_len, new_name);

	from_inode = BTRFS_I(from_dentry->d_inode);
	to_inode = BTRFS_I(to_dentry->d_inode);

	from_location = &from_inode->location;
	to_location = &to_inode->location;

	BTRFS_SUB_DBG(TX, "Change root: 'from' key = [%lld %d %lld], "
			"'to' key = [%lld %d %lld]\n",
			from_location->objectid, from_location->type, from_location->offset,
			to_location->objectid, to_location->type, to_location->offset);

	from_root = from_inode->root;
	to_root = to_inode->root;

	from_root_key = &from_inode->root->root_key;
	to_root_key = &to_inode->root->root_key;

	BTRFS_SUB_DBG(TX, "Change root: 'from' root key = [%lld %d %lld], "
			"'to' root key = [%lld %d %lld]\n",
			from_root_key->objectid, from_root_key->type, from_root_key->offset,
			to_root_key->objectid, to_root_key->type, to_root_key->offset);

	// the whole search process, excluding everything after 'btrfs_search_slot'
	// could have been done using 'btrfs_find_root_ref'.

	trans = btrfs_start_transaction(from_root->fs_info->tree_root, 2);
	btrfs_record_root_in_trans(trans, from_root->fs_info->tree_root);

	get_fs_root_dir_item(trans, from_file);

	btrfs_commit_transaction(trans, from_root->fs_info->tree_root);

	kfree(to_name);
err_free_from_name:
	kfree(from_name);
err_fput:
	fput(to_file);
	fput(from_file);

	return ret;
}


/* A snapshot item contains all the informations required to find a snapshot,
 * obtain its root or delete it.
 *
 * A snapshot item shall not contain informations regarding the course of
 * transactions, as that would burden the file system with accesses, and could
 * even grow the snapshot item to undesirable proportions --- and it is quite
 * big as it is.
 */
int btrfs_insert_snapshot_item(struct btrfs_trans_handle * trans,
		struct btrfs_root * tree_root, struct btrfs_key * src_key,
		struct btrfs_key * snap_key,
		u64 dir, struct dentry * dentry, u64 dir_index)
{
	struct btrfs_acid_snapshot_item * item;
	struct btrfs_key key;
	struct btrfs_disk_key snap_disk_key, src_disk_key;
	struct btrfs_path * path;
	struct extent_buffer * leaf;
	unsigned long ptr;
	int ret = 0;

	if (!trans || !tree_root || !src_key || !snap_key || !dentry)
		return -EINVAL;

//	item = kzalloc(sizeof(*item) + dentry->d_name.len, GFP_KERNEL);
//	if (!item)
//		return -ENOMEM;

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	key.objectid = src_key->objectid;
	key.type = BTRFS_ACID_SNAPSHOT_ITEM_KEY;
	key.offset = snap_key->objectid;

	ret = btrfs_insert_empty_item(trans, tree_root, path, &key,
				sizeof(*item) + dentry->d_name.len);
	BUG_ON(ret);

	leaf = path->nodes[0];
	item = btrfs_item_ptr(leaf, path->slots[0],
			struct btrfs_acid_snapshot_item);

	btrfs_cpu_key_to_disk(&snap_disk_key, snap_key);
	btrfs_cpu_key_to_disk(&src_disk_key, src_key);
	btrfs_set_snapshot_snap_key(leaf, item, &snap_disk_key);
	btrfs_set_snapshot_src_key(leaf, item, &src_disk_key);
	btrfs_set_snapshot_owner_pid(leaf, item, current->pid);
	btrfs_set_snapshot_dirid(leaf, item, dir);
	btrfs_set_snapshot_dir_index(leaf, item, dir_index);
	btrfs_set_snapshot_name_len(leaf, item, dentry->d_name.len);
	ptr = (unsigned long) (item + 1);
	write_extent_buffer(leaf, dentry->d_name.name, ptr, dentry->d_name.len);

	btrfs_mark_buffer_dirty(leaf);
	btrfs_free_path(path);


//	btrfs_cpu_key_to_disk(&item->snap_key, snap_key);
//	btrfs_cpu_key_to_disk(&item->src_key, src_key);
//	item->owner_pid = cpu_to_le64(current->pid);
//	item->dirid = cpu_to_le64(dir);
//	item->dir_index = cpu_to_le64(dir_index);
//	item->name_len = dentry->d_name.len;

//	ret = btrfs_insert_item(trans, tree_root, &key, item, sizeof(*item));
//	BUG_ON(ret);

	return 0;
}

int btrfs_delete_snapshot_item(struct btrfs_trans_handle * trans,
		struct btrfs_root * root, struct btrfs_key * location)
{
	struct btrfs_path * path;
	int ret;

	if (!trans || !root || !location)
		return -EINVAL;

	BTRFS_SUB_DBG(TX, "location [%llu %d %llu]\n",
			location->objectid, location->type, location->offset);

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	ret = btrfs_search_slot(trans, root, location, path, -1, 1);
	BUG_ON(ret < 0);
	if (ret > 0)
	{
		ret = -ENOENT;
		goto out;
	}
	ret = btrfs_del_item(trans, root, path);
	BUG_ON(ret);

	BTRFS_SUB_DBG(TX, "Deleted item.\n");

out:
	btrfs_free_path(path);
	return ret;
}

int btrfs_insert_tx_subvol_item(struct btrfs_trans_handle * trans,
		struct btrfs_root * tree_root, struct btrfs_key * subvol_key,
		struct qstr * subvol_name, unsigned long parent_ino)
{
	int ret = 0;
	struct btrfs_acid_tx_subvol_item * item;
	struct btrfs_path * path;
	struct btrfs_key key;
	struct btrfs_disk_key disk_key;
	struct extent_buffer * leaf;
	unsigned long ptr;

	if (!trans || !tree_root || !subvol_key || !subvol_name)
		return -EINVAL;

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	key.objectid = subvol_key->objectid;
	key.type = BTRFS_ACID_TX_SUBVOL_ITEM_KEY;
	key.offset = 0;

	ret = btrfs_insert_empty_item(trans, tree_root, path, &key,
			sizeof(*item) + subvol_name->len);
	BUG_ON(ret);

	leaf = path->nodes[0];
	item = btrfs_item_ptr(leaf, path->slots[0],
			struct btrfs_acid_tx_subvol_item);

	btrfs_cpu_key_to_disk(&disk_key, subvol_key);
	btrfs_set_tx_subvol_key(leaf, item, &disk_key);
	btrfs_set_tx_subvol_parent_dirid(leaf, item, parent_ino);
	btrfs_set_tx_subvol_name_len(leaf, item, subvol_name->len);
	ptr = (unsigned long) (item + 1);
	write_extent_buffer(leaf, subvol_name->name, ptr, subvol_name->len);

	btrfs_mark_buffer_dirty(leaf);
	btrfs_free_path(path);

	return 0;
}



int btrfs_acid_file_open(struct inode * inode, struct file * file)
{
	struct dentry * fdentry = file->f_path.dentry;
	struct btrfs_inode * our_inode = BTRFS_I(inode);

	BTRFS_SUB_DBG(CALL, "inode ino = %lu [%llu %d %llu], file: %.*s\n",
			inode->i_ino,
			our_inode->location.objectid,
			our_inode->location.type,
			our_inode->location.offset,
			fdentry->d_name.len, fdentry->d_name.name);

	return 0;
}

void btrfs_acid_vm_open(struct vm_area_struct * area)
{
	struct dentry * d = area->vm_file->f_path.dentry;

	BTRFS_SUB_DBG(CALL, "file = %.*s\n",
			d->d_name.len, d->d_name.name);
}

int btrfs_acid_destroy_snapshot(struct btrfs_acid_snapshot * snap,
		struct btrfs_fs_info * fs_info)
{
	struct inode * parent_inode;
	struct inode * snap_inode;
//	struct dentry * parent_dentry;
//	struct dentry * snap_dentry;
	struct btrfs_trans_handle * trans;
	struct btrfs_key parent_location;
	struct btrfs_key snap_inode_location;
	struct btrfs_key snap_item_key;
	struct btrfs_path * path;
	struct btrfs_dir_item * di;
	int ret = 0, err = 0;

	if (!snap || !fs_info)
		return -EINVAL;

	if (!snap->root || !snap->location || !snap->src_location)
		return -EINVAL;

	parent_location.objectid = snap->parent_ino;
	parent_location.type = BTRFS_INODE_ITEM_KEY;
	parent_location.offset = 0;

	parent_inode = btrfs_iget(fs_info->sb, &parent_location,
			fs_info->fs_root, NULL);
	if (IS_ERR_OR_NULL(parent_inode))
		return (IS_ERR(parent_inode) ? PTR_ERR(parent_inode) : -ENOENT);

	snap_inode_location.objectid = btrfs_root_dirid(&snap->root->root_item);
	snap_inode_location.type = BTRFS_INODE_ITEM_KEY;
	snap_inode_location.offset = 0;

	snap_inode = btrfs_iget(fs_info->sb, &snap_inode_location,
			snap->root, NULL);
	if (IS_ERR_OR_NULL(snap_inode))
		return (IS_ERR(snap_inode) ? PTR_ERR(snap_inode) : -ENOENT);

	BTRFS_SUB_DBG(FS, "snap_inode [%llu %d %llu]\n",
			snap_inode_location.objectid, snap_inode_location.type,
			snap_inode_location.offset);
	BTRFS_SUB_DBG(FS, "location [%llu %d %llu]\n",
			snap->location->objectid, snap->location->type,
			snap->location->offset);
	BTRFS_SUB_DBG(FS, "snap inode = %llu\n", snap_inode->i_ino);

	if (snap_inode->i_ino != BTRFS_FIRST_FREE_OBJECTID)
		return -EINVAL;

	down_write(&fs_info->subvol_sem);

	trans = btrfs_start_transaction(fs_info->fs_root, 0);
	if (IS_ERR(trans))
	{
		err = PTR_ERR(trans);
		goto out_up_write;
	}
	trans->block_rsv = &fs_info->global_block_rsv;

	ret = btrfs_unlink_subvol(trans, fs_info->fs_root, parent_inode,
			snap->root->root_key.objectid,
			snap->path.name,
			snap->path.len);
	BUG_ON(ret);

	btrfs_record_root_in_trans(trans, snap->root);

	memset(&snap->root->root_item.drop_progress, 0,
			sizeof(snap->root->root_item.drop_progress));
	snap->root->root_item.drop_level = 0;
	btrfs_set_root_refs(&snap->root->root_item, 0);

	if (!xchg(&snap->root->orphan_item_inserted, 1)) {
		ret = btrfs_insert_orphan_item(trans,
				fs_info->tree_root,
				snap->root->root_key.objectid);
		BUG_ON(ret);
	}

	/* remove the snapshot item from the tree root */
	snap_item_key.objectid = snap->src_location->objectid;
	snap_item_key.type = BTRFS_ACID_SNAPSHOT_ITEM_KEY;
	snap_item_key.offset = snap->location->objectid;
	err = btrfs_delete_snapshot_item(trans, fs_info->tree_root, &snap_item_key);
	BUG_ON(err);
	btrfs_record_root_in_trans(trans, fs_info->tree_root);

//	ret = btrfs_end_transaction(trans, fs_info->fs_root);
	ret = btrfs_commit_transaction(trans, fs_info->fs_root);
	BUG_ON(ret);

	BTRFS_SUB_DBG(FS, "Snapshot [%llu %d %llu] unlinked.\n",
			snap->root->root_key.objectid, snap->root->root_key.type,
			snap->root->root_key.offset);

	snap_inode->i_flags |= S_DEAD;

out_up_write:
	up_write(&fs_info->subvol_sem);
	iput(snap_inode);
	iput(parent_inode);

	if (!err)
	{
		BTRFS_SUB_DBG(FS, "Invalidating inodes.\n");
		shrink_dcache_sb(fs_info->sb);
		btrfs_invalidate_inodes(snap->root);

		ret = RB_EMPTY_ROOT(&snap->root->inode_tree);
		BTRFS_SUB_DBG(FS, "Inode tree free = %d\n", ret);
	}

	return (err ? err : 0);
}

/* We have a pretty serious issue with this method, which we shall leave for
 * tomorrow's me to deal with: we create a pending snapshot, the snapshot is
 * created, but we have no info on which root the snapshot has. I.e., we're
 * blind here. We need to have that information so we can insert it into the
 * god forsaken tree of snapshots.
 *
 * Tomorrow-me, GL. I'm going home now.
 *
 * 	Dear yesterday-me,
 * 		you're full of shit.
 * 		Apparently, the snapshot root is returned in 'pending->snap', and you
 * 		used to know this.
 *
 */
struct btrfs_acid_snapshot *
btrfs_acid_create_snapshot(struct dentry * txsv_dentry)
{
	struct btrfs_root * src_root;
	struct btrfs_pending_snapshot * pending;
	struct btrfs_trans_handle * trans;
	struct btrfs_acid_snapshot * snap = NULL;
	struct btrfs_acid_ctl * ctl;
	struct qstr snap_path;
	struct dentry * snap_dentry;
	struct inode * dir;
	int ret = 0;

	src_root = BTRFS_I(txsv_dentry->d_inode)->root;
	ctl = &src_root->fs_info->acid_ctl;
	dir = txsv_dentry->d_parent->d_inode;

	BTRFS_SUB_DBG(FS, "Creating Snapshot for PID = %d\n",
			current->pid);

	pending = kzalloc(sizeof(*pending), GFP_NOFS);
	if (!pending)
	{
		snap = ERR_PTR(-ENOMEM);
		goto out;
	}

	/* Do we want to down for read or for write?
	 * 'create_snapshot()', in ioctl.c, just doesn't down it at all, therefore
	 * we're doing pretty much the same. */
//	down_read(&src_root->fs_info->subvol_sem);

	__snapshot_create_path(ctl, &snap_path, current->pid);
	BTRFS_SUB_DBG(FS,
			"Snapshot path: name = %.*s, len = %d, hash = %d\n",
			snap_path.len, snap_path.name, snap_path.len, snap_path.hash);

	mutex_lock_nested(&dir->i_mutex, I_MUTEX_PARENT);

	pending->dentry = lookup_one_len(snap_path.name,
			txsv_dentry->d_parent, snap_path.len);
	if (IS_ERR(pending->dentry))
	{
		snap = ERR_CAST(pending->dentry);
		goto out_unlock_mutex;
	}
	BTRFS_SUB_DBG(FS, "Pending dentry: name = %.*s, hash = %d\n",
			pending->dentry->d_name.len, pending->dentry->d_name.name,
			pending->dentry->d_name.hash);

	if (pending->dentry->d_inode)
	{
		snap = ERR_PTR(-EEXIST);
		goto out_put_dentry;
	}

	pending->acid_tx = 1;
	pending->root = src_root;

	btrfs_init_block_rsv(&pending->block_rsv);

	/* #notanymore two items: 1 root item, 1 snapshot item */
	/* six items: two for root back/forward refs, two for directory entries
	 * and one for root of the snapshot, plus one for the snapshot item. */

	trans = btrfs_start_transaction(src_root->fs_info->extent_root, 6);
	if (IS_ERR(trans))
	{
		snap = ERR_CAST(trans);
		goto out_put_dentry;
	}

	ret = btrfs_snap_reserve_metadata(trans, pending);
	BUG_ON(ret);

	list_add(&pending->list, &trans->transaction->pending_snapshots);

	ret = btrfs_commit_transaction(trans, src_root->fs_info->extent_root);
	BUG_ON(ret);

	BTRFS_SUB_DBG(FS, "Transaction committed.\n");

	ret = pending->error;
	if (ret)
		goto out_put_dentry;

	btrfs_orphan_cleanup(pending->snap);

	/* From this point forward, whenever we have an error we *have* to remove
	 * the snapshot item from the root tree, as well as the snapshot's tree.
	 */

	/* Adds the snapshot to the snapshot's tree */
	snap = __snapshot_add(pending->snap, &snap_path);
	if (!snap || IS_ERR(snap))
	{
		BTRFS_SUB_DBG(FS,
				"Failed to add snapshot to ACID CTL\n");
		goto err_compensate_trans;
	}

	BTRFS_SUB_DBG(FS, "Snapshot key [%llu %d %llu]\n",
			pending->snap->root_key.objectid,
			pending->snap->root_key.type,
			pending->snap->root_key.offset);

	/* From this point forward, whenever we have an error we *have* to remove
	 * the snapshot from the 'current_snapshots' tree.
	 */

	snap_dentry = __snapshot_instantiate_dentry(pending->dentry);
	if (!snap_dentry || IS_ERR(snap_dentry))
	{
		BTRFS_SUB_DBG(FS, "Failed to instantiate dentry\n");
		__snapshot_remove(ctl);
		goto err_compensate_trans;
	}
	__snapshot_set_perms(dir, snap_dentry);

	/* set the root's snapshot */
	pending->snap->snap = snap;

out_put_dentry:
	if (ret) // only happens if execution comes from commit transaction.
		snap = ERR_PTR(ret);
	else
		fsnotify_mkdir(dir, pending->dentry);
	d_drop(pending->dentry);
	dput(pending->dentry);

out_unlock_mutex:
	mutex_unlock(&dir->i_mutex);
	__snapshot_destroy_path(&snap_path);
	kfree(pending);
out:
	BTRFS_SUB_DBG(FS, "Returning\n");
	return snap;

/* Handle an extraordinary error condition. */
err_compensate_trans:
	/* Remove the snapshot item and the snapshot tree */
	goto out_put_dentry;
}

int btrfs_acid_create_snapshot_by_ioctl(struct file * file,
		struct btrfs_ioctl_acid_create_snapshot_args * args)
{
	struct file * src_file;
	int ret = 0;

	if (!args)
		return -EINVAL;

	src_file = fget(args->src_fd);
	if (!src_file)
		return -EINVAL;


	ret = (btrfs_acid_create_snapshot(fdentry(src_file)) == NULL);

	fput(src_file);
	return ret;
}

int btrfs_acid_set_tx_subvol(struct file * file,
		struct btrfs_ioctl_acid_subvol_flags_args * args)
{
	int ret = 0;
	struct inode * inode;
	struct btrfs_inode * sub_inode;
	struct btrfs_root * sub_root;
	u64 initial_flags, final_flags;
	struct btrfs_trans_handle * trans;
	struct dentry * dentry, * dentry_parent;
	struct btrfs_acid_snapshot * txsv;

	if (!args)
		return -EINVAL;

	/* TODO: check for permission to do this */

	dentry = fdentry(file);
	inode = dentry->d_inode;

	BTRFS_SUB_DBG(TX, "dentry name: %.*s\n",
			dentry->d_name.len, dentry->d_name.name);
	BTRFS_SUB_DBG(TX, "parent name: %.*s, inode: %lu\n",
			dentry->d_parent->d_name.len, dentry->d_parent->d_name.name,
			dentry->d_parent->d_inode->i_ino);

	BTRFS_SUB_DBG(TX, "dentry name hash: %u, our hash: %u\n",
			dentry->d_name.hash,
			full_name_hash(dentry->d_name.name, dentry->d_name.len));

	if (inode->i_ino != BTRFS_FIRST_FREE_OBJECTID)
		return -EINVAL;

	sub_inode = BTRFS_I(inode);
	sub_root = sub_inode->root;

	/* First of, check if a transactional subvolume exists. Currently, we
	 * will only support a single transactional subvolume, although we believe
	 * it wouldn't be that hard to support several.
	 */
	/* Acquire sv's semaphore for writing. We might do it anyway, so lock it
	 * for writing now and either release it as soon as we check that a tx sv
	 * already exists, or keep it until we finish the whole operation, while
	 * avoiding some other dude beating us to it.
	 */
	down_write(&sub_root->fs_info->acid_ctl.sv_sem);
	if (sub_root->fs_info->acid_ctl.sv != NULL)
	{
		ret = -EEXIST;
		goto out_up_write_sv;
	}

	down_write(&sub_root->fs_info->subvol_sem);
	initial_flags = btrfs_root_flags(&sub_root->root_item);
	final_flags = initial_flags;

	BTRFS_SUB_DBG(TX, "Subvol initial flags: %llu\n", initial_flags);

	if (initial_flags & BTRFS_ROOT_SUBVOL_ACID)
		goto out_up_write; /* subvolume already flagged as transactional. */

	final_flags |= BTRFS_ROOT_SUBVOL_ACID;

	BTRFS_SUB_DBG(TX, "Subvol final flags: %llu\n", final_flags);

	btrfs_set_root_flags(&sub_root->root_item, final_flags);

	/* We will change a root item and add a new btrfs_tx_subvol_item, so
	 * we require 2 changes.
	 */
	trans = btrfs_start_transaction(sub_root->fs_info->extent_root, 2);
	if (IS_ERR(trans))
	{
		ret = PTR_ERR(trans);
		goto out_reset_flags;
	}
	btrfs_record_root_in_trans(trans, sub_root->fs_info->tree_root);

	ret = btrfs_update_root(trans, sub_root->fs_info->tree_root,
			&sub_root->root_key, &sub_root->root_item);

	dentry_parent = dget_parent(dentry);
	ret = btrfs_insert_tx_subvol_item(trans, sub_root->fs_info->tree_root,
			&sub_root->root_key,
			&dentry->d_name, dentry_parent->d_inode->i_ino);

	btrfs_commit_transaction(trans, sub_root);

	txsv = fill_acid_txsv(sub_root, &sub_root->root_key,
			dentry_parent->d_inode->i_ino,
			(char *) dentry->d_name.name, dentry->d_name.len);
	sub_root->fs_info->acid_ctl.sv = txsv;

	d_drop(dentry);
	dput(dentry_parent);

out_reset_flags:
	if (ret)
	{
		BTRFS_SUB_DBG(TX, "Resetting Subvol flags\n");
		btrfs_set_root_flags(&sub_root->root_item, initial_flags);
	}

out_up_write:
	up_write(&sub_root->fs_info->subvol_sem);
out_up_write_sv:
	up_write(&sub_root->fs_info->acid_ctl.sv_sem);
	return ret;
}

/* Cleans up the lost snapshots in the tree. */
int btrfs_acid_init_cleanup(struct btrfs_fs_info * fs_info)
{
	struct btrfs_root * tree_root;
	struct btrfs_key search_key;
	struct btrfs_path * path;
	struct btrfs_trans_handle * trans;
	struct extent_buffer * leaf;
	struct btrfs_key found_key, snap_key, src_key;
	struct btrfs_disk_key disk_key, snap_disk_key, src_disk_key;
	struct btrfs_acid_snapshot_item * si;
	struct btrfs_acid_snapshot * snap;
	struct list_head found_snaps;
	struct snapshot_list * snap_entry, * tmp_entry;
	int slot, i, total_nodes;
	int ret = 0, err = 0;

	if (!fs_info)
		return -EINVAL;

	tree_root = fs_info->tree_root;
	search_key.objectid = 0;
	search_key.type = BTRFS_ACID_SNAPSHOT_ITEM_KEY;
	search_key.offset = 0;

	BTRFS_SUB_DBG(TX, "Allocating path\n");
	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	/* To try: search the tree, COW on; then, release the path.
	 * After that, for each node, start a transaction and remove the snapshot
	 * items within its leaf: one transaction per item, use 'end_transaction'
	 * instead of 'commit' to ease the burden on the fs.
	 * Pray it works.
	 */

	BTRFS_SUB_DBG(TX, "Searching slots\n");
	/* Find all snapshot items in the root tree. */
	ret = btrfs_search_slot(NULL, tree_root, &search_key, path, 0, 0);
	BUG_ON(ret < 0);

	INIT_LIST_HEAD(&found_snaps);

	i = 1;
	total_nodes = 0;
	while (1)
	{
		leaf = path->nodes[0];
		slot = path->slots[0];
		if (slot >= btrfs_header_nritems(leaf))
		{
			total_nodes ++;
			i++;
			ret = btrfs_next_leaf(tree_root, path);
			if (ret != 0) /* no more leafs. */
				break;

			leaf = path->nodes[0];
			slot = path->slots[0];
		}

		btrfs_item_key(leaf, &disk_key, slot);
		btrfs_disk_key_to_cpu(&found_key, &disk_key);

//		BTRFS_TX_DBG("INIT-CLEANUP", "Found key type = %d\n", found_key.type);

		if (btrfs_key_type(&found_key) != BTRFS_ACID_SNAPSHOT_ITEM_KEY)
			goto loop_again;

		BTRFS_SUB_DBG(TX, "Found Snapshot item: [%llu %d %llu]\n",
				found_key.objectid, found_key.type, found_key.offset);

		si = btrfs_item_ptr(leaf, slot, struct btrfs_acid_snapshot_item);
		if (IS_ERR_OR_NULL(si))
		{
			err = (!si ? -ENOENT : PTR_ERR(si));
			break;
		}

		snap = __snapshot_read_leaf(leaf, si);
		if (IS_ERR(snap))
		{
			err = PTR_ERR(snap);
			break;
		}

		snap_entry = kzalloc(sizeof(*snap_entry), GFP_NOFS);
		if (!snap_entry)
		{
			// __snapshot_destroy(snap);
			err = -ENOMEM;
			break;
		}

		snap_entry->snap = snap;
		list_add(&snap_entry->list, &found_snaps);

		BTRFS_SUB_DBG(TX,
				"Snapshot Item: snap key = [%llu %d %llu], "
				"src key = [%llu %d %llu]\n",
				snap->location->objectid, snap->location->type,
				snap->location->offset,
				snap->src_location->objectid, snap->src_location->type,
				snap->src_location->offset);
		BTRFS_SUB_DBG(TX,
				"Snapshot Item: dirid = %llu, index = %llu, owner = %llu, "
				"name len = %d, name = %.*s\n",
				snap->parent_ino, snap->dir_index,
				(unsigned long long) snap->owner_pid,
				snap->path.len, snap->path.len, snap->path.name);
		BTRFS_SUB_DBG(TX, "--------------\n");

loop_again:
		path->slots[0] ++;
	}

	btrfs_free_path(path);
	if (err)
		goto out;

	list_for_each_entry(snap_entry, &found_snaps, list)
	{
		snap = snap_entry->snap;
		if (!snap->root)
		{
			snap->root = btrfs_read_fs_root_no_name(fs_info, snap->location);
			if (IS_ERR_OR_NULL(snap->root))
			{
				BTRFS_SUB_DBG(TX,
						"Unable to find root for [%llu %d %llu]\n",
						snap->location->objectid,
						snap->location->type, snap->location->offset);
				continue;
			}
			btrfs_acid_destroy_snapshot(snap, fs_info);
		}
	}

	list_for_each_entry_safe(snap_entry, tmp_entry, &found_snaps, list)
	{
		if (!snap_entry) continue;

		snap = snap_entry->snap;
		if (!snap)
			goto list_free_entry;

		__snapshot_destroy(snap);

list_free_entry:
		list_del(&snap_entry->list);
		kfree(snap_entry);
	}

//	BTRFS_TX_DBG("INIT-CLEANUP", "Found %d leafs with items.\n", total_nodes);
//
//	for (i = 0, leaf = path->nodes[i]; i < total_nodes; i ++)
//		BTRFS_TX_DBG("INIT-CLEANUP", "leaf %p with %d slots\n",
//				leaf, path->slots[i]);


out:
	return (err ? err : 0);
}

int btrfs_acid_init(struct btrfs_fs_info * fs_info)
{
	struct btrfs_acid_ctl * ctl;
	struct btrfs_acid_snapshot * txsv;
	int ret = 0;

	if (!fs_info)
		return -EINVAL;

	ctl = &fs_info->acid_ctl;

	init_rwsem(&ctl->sv_sem);
	init_rwsem(&ctl->curr_snaps_sem);

	INIT_RADIX_TREE(&ctl->current_snapshots, GFP_ATOMIC);
	ctl->sv = NULL;

	txsv = find_acid_subvol(fs_info->tree_root);
	if (txsv == NULL)
		goto out;

	down_write(&ctl->sv_sem);
	ctl->sv = txsv;
	up_write(&ctl->sv_sem);

	ret = btrfs_acid_init_cleanup(fs_info);
	if (ret)
		BTRFS_SUB_DBG(TX, "Cleanup returned error %d\n", ret);

	atomic_set(&ctl->clock, 0);

out:
	return ret;
}

/* Reads a snapshot item from a leaf, as long as the 'leaf' extent buffer
 * exists and 'si' is the correct snapshot item offset.
 * This method will return a struct btrfs_acid_snapshot filled only with the
 * data available on the leaf. This means it will not fill the 'root' field, as
 * that information must be looked up in-memory. That is somebody else's job.
 */
static struct btrfs_acid_snapshot *
__snapshot_read_leaf(struct extent_buffer * leaf,
		struct btrfs_acid_snapshot_item * si)
{
	struct btrfs_acid_snapshot * snap;
	struct btrfs_disk_key snap_disk_key, src_disk_key;
	int err;

	if (!leaf || !si)
		return ERR_PTR(-EINVAL);
	if (IS_ERR(leaf))
		return ERR_CAST(leaf);
	if (IS_ERR(si))
		return ERR_CAST(si);

	err = -ENOMEM;
	snap = kzalloc(sizeof(*snap), GFP_NOFS);
	if (!snap)
		goto err;
	snap->location = kzalloc(sizeof(*snap->location), GFP_NOFS);
	if (!snap->location)
		goto err_free_snap;
	snap->src_location = kzalloc(sizeof(*snap->src_location), GFP_NOFS);
	if (!snap->src_location)
		goto err_free_snap_location;

	btrfs_snapshot_snap_key(leaf, si, &snap_disk_key);
	btrfs_snapshot_src_key(leaf, si, &src_disk_key);
	BTRFS_SUB_DBG(FS,
			"snap disk key [%llu %d %llu] src disk key [%llu %d %llu]\n",
			snap_disk_key.objectid, snap_disk_key.type, snap_disk_key.offset,
			src_disk_key.objectid, src_disk_key.type, src_disk_key.offset);

	btrfs_disk_key_to_cpu(snap->location, &snap_disk_key);
	btrfs_disk_key_to_cpu(snap->src_location, &src_disk_key);
	snap->owner_pid = btrfs_snapshot_owner_pid(leaf, si);
	snap->parent_ino = btrfs_snapshot_dirid(leaf, si);
	snap->dir_index = btrfs_snapshot_dir_index(leaf, si);
	snap->path.len = btrfs_snapshot_name_len(leaf, si);

	snap->path.name = kzalloc(sizeof(char) * snap->path.len, GFP_NOFS);
	if (!snap->path.name)
		goto err_free_src_location;

	err = -ENOENT;
	read_extent_buffer(leaf, (void *) snap->path.name, (unsigned long)(si + 1),
						snap->path.len);
	if (!snap->path.name)
		goto err_free_path_name;

	snap->path.hash = full_name_hash(snap->path.name, snap->path.len);
	snap->hash = btrfs_name_hash(snap->path.name, snap->path.len);

	return snap;

err_free_path_name:
	kfree(snap->path.name);
err_free_src_location:
	kfree(snap->src_location);
err_free_snap_location:
	kfree(snap->location);
err_free_snap:
	kfree(snap);
err:
	return ERR_PTR(err);
}

/* Destroys a struct btrfs_acid_snapshot previously created by
 * __snapshot_create(), freeing all the pointer members that are non-null,
 * and finishing by freeing the struct itself, setting the 'snap' pointer to
 * NULL.
 */
static int __snapshot_destroy(struct btrfs_acid_snapshot * snap)
{
	if (!snap)
		return -EINVAL;

	if (snap->location)	kfree(snap->location);
	if (snap->src_location) kfree(snap->src_location);
	if (snap->path.name) kfree(snap->path.name);

	kfree(snap);
	snap = NULL;

	return 0;
}

static int __snapshot_set_perms(struct inode * dir, struct dentry * dentry)
{
	struct iattr attrs;
	struct inode * inode;

	if (!dir || !dentry)
	{
		BTRFS_SUB_DBG(FS, "Invalid arguments!\n");
		return -EINVAL;
	}
	inode = dentry->d_inode;

	attrs.ia_uid = current_uid();
	attrs.ia_gid = current_gid();

	attrs.ia_mode = inode->i_mode | S_IFDIR | S_IRWXU | S_IRWXG | S_IRWXO;
	attrs.ia_valid = ATTR_MODE | ATTR_UID | ATTR_GID;

	BTRFS_SUB_DBG(FS,
			"dentry = %.*s, mode = %d, valid = %d, uid = %d, gid = %d\n",
			dentry->d_name.len, dentry->d_name.name,
			attrs.ia_mode, attrs.ia_valid, attrs.ia_uid, attrs.ia_gid);

	return notify_change(dentry, &attrs);
}

static struct dentry *
__snapshot_instantiate_dentry(struct dentry * dentry)
{
	struct dentry * parent;
	struct inode * inode;

	parent = dget_parent(dentry);
	inode = btrfs_lookup_dentry(parent->d_inode, dentry);
	dput(parent);
	if (IS_ERR(inode))
	{
		dentry = ERR_CAST(inode);
		goto fail;
	}
	BUG_ON(!inode);
	d_instantiate(dentry, inode);

fail:
	return dentry;
}

/* Creates a new struct btrfs_acid_snapshot representing the snapshot with
 * root at 'root' and path at 'path', and add it to the 'current_snapshots'
 * tree in 'struct btrfs_acid_ctl', associating it with the current process'
 * id (PID).
 *
 * This method does not set the 'location' and 'src_location' fields in the
 * struct, as they are not important in the current context. As this method
 * will probably be called from within the method creating the snapshot, and
 * as these snapshots are to be ephemeral, either disappearing after an
 * unsuccessful commit or becoming the TxSv, we have all the required
 * informations in-memory: the snapshot key is kept by the snapshot's root, and
 * the source key is kept by the TxSv's root.
 *
 * - Anyway, it is probably best to set those fields, just in case we forget
 * this pretty little rule and end up trying to dereference a bunch of zeros.
 */
static struct btrfs_acid_snapshot *
__snapshot_add(struct btrfs_root * root, struct qstr * path)
{
	struct btrfs_acid_ctl * ctl;
	struct btrfs_acid_snapshot * snap;
	int ret = 0;

	if (!root)
		return ERR_PTR(-EINVAL);

	ctl = &root->fs_info->acid_ctl;

	snap = kzalloc(sizeof(*snap), GFP_NOFS);
	if (!snap)
		return ERR_PTR(-ENOMEM);

	/* lookup snapshot item -- Why? */

	snap->location = btrfs_acid_copy_key(&root->root_key);
	if (IS_ERR(snap->location))
	{
		kfree(snap);
		return ERR_CAST(snap->location);
	}

	down_read(&ctl->sv_sem);
	BUG_ON(!ctl->sv->location);
	snap->src_location = btrfs_acid_copy_key(ctl->sv->location);
	up_read(&ctl->sv_sem);

//	snap->location = &root->root_key;
	snap->root = root;
	snap->owner_pid = current->pid;

	INIT_LIST_HEAD(&snap->known_pids);
	init_rwsem(&snap->known_pids_sem);

	/* Create a snapshot name and hash for dcache, and also create an hash
	 * for our own comparing purposes.
	 */
	/* snapshot path creation must happen back in btrfs_acid_create_snapshot
	 * so we can create a dentry and use it during the pending snapshot
	 * creation.
	 */
	snap->path.name = kzalloc(sizeof(*path->name) * path->len, GFP_NOFS);
	if (!snap->path.name)
	{
		kfree(snap);
		return ERR_PTR(-ENOMEM);
	}
	memcpy((void *) snap->path.name, (void *) path->name, path->len);
	snap->path.len = path->len;
	snap->path.hash = path->hash;
	snap->hash = btrfs_name_hash(path->name, path->len);

	/* Initiate read/write logs */
	INIT_LIST_HEAD(&snap->read_log);
	INIT_LIST_HEAD(&snap->write_log);

	/* Snapshot entry created; now we must insert it to the snapshot's tree. */
	down_write(&ctl->curr_snaps_sem);
	ret = radix_tree_insert(&ctl->current_snapshots, snap->owner_pid, snap);

	if (ret)
	{
		kfree(snap);
		snap = ERR_PTR(ret);
	}

	up_write(&ctl->curr_snaps_sem);

	return snap;
}

static int __snapshot_remove(struct btrfs_acid_ctl * ctl)
{
	return __snapshot_remove_pid(ctl, current->pid);
}

static int __snapshot_remove_pid(struct btrfs_acid_ctl * ctl, pid_t pid)
{
	struct btrfs_acid_snapshot * snap;
	if (!ctl)
		return -EINVAL;

	BTRFS_SUB_DBG(FS,
			"Deleting Snapshot for PID = %d\n", pid);

	down_write(&ctl->curr_snaps_sem);
	snap = radix_tree_delete(&ctl->current_snapshots, pid);
	up_write(&ctl->curr_snaps_sem);

	BTRFS_SUB_DBG(FS,
			"Snapshot %p removed from the tree\n", snap);

	if (!snap)
		return 0; // it does not exist, which is good from our POV.

	if (snap->path.name)
		kfree(snap->path.name);

	kfree(snap);

	return 0;
}

static int __snapshot_create_path(struct btrfs_acid_ctl * ctl,
		struct qstr * path, pid_t pid)
{
	int ret = 0;
	/* we are assuming that 'pid' may have up to 20 chars; if the pid is by
	 * any chance a 64-bit value, iirc, it would be bound by a maximum of
	 * 20 characters of length. Therefore, '#pid\0' == 22 chars.
	 */
	char tmp_name[22];
	int tmp_name_len;
	char * final_name;
	int final_name_len;

	snprintf(tmp_name, 22, "#%d", pid);
	tmp_name_len = strlen(tmp_name);

	down_read(&ctl->sv_sem);
	BTRFS_SUB_DBG(FS, "TxSv name = %.*s, len = %d\n",
			ctl->sv->path.len, ctl->sv->path.name, ctl->sv->path.len);
	final_name_len = tmp_name_len + ctl->sv->path.len;
	final_name = kzalloc(sizeof(*final_name) * final_name_len, GFP_NOFS);
	if (!final_name)
	{
		ret = -ENOMEM;
		goto out;
	}

	memcpy(final_name, ctl->sv->path.name, ctl->sv->path.len);
	memcpy(final_name+ctl->sv->path.len, tmp_name, tmp_name_len);

	BTRFS_SUB_DBG(FS, "Final name = %.*s, len = %d\n",
			final_name_len, final_name, final_name_len);

	path->len = final_name_len;
	path->name = final_name;
	path->hash = full_name_hash(path->name, path->len);

out:
	up_read(&ctl->sv_sem);
	return ret;
}

static void __snapshot_destroy_path(struct qstr * path)
{
	if (!path)
		return;

	kfree(path->name);
}



/* Wrapper for 'do_sync_read', which creates a read-set entry. */
ssize_t btrfs_acid_sync_read(struct file * file,
		char __user * args, size_t len, loff_t * ppos)
{
	int pos = *ppos;
	int first = pos >> PAGE_CACHE_SHIFT;
	int last = (len + PAGE_CACHE_SIZE-1) >> PAGE_CACHE_SHIFT;

	struct inode * f_inode = file->f_path.dentry->d_inode;
	struct btrfs_inode * inode;
	struct btrfs_key * location;
	ssize_t ret;

	ret = btrfs_acid_allow(f_inode);
	if (ret < 0) {
		BTRFS_SUB_DBG(ACCESS, "Refused access to PID %d\n", current->pid);
		return ret;
	}

	ret = do_sync_read(file, args, len, ppos);
	if (ret < 0)
		goto out;

	inode = BTRFS_I(f_inode);
	if (!inode)
		return -EINVAL;
	location = &inode->location;

	BUG_ON(!inode->root->snap);
	btrfs_acid_log_read(inode->root->snap, location, first, last);
out:
	return ret;
}

ssize_t btrfs_acid_sync_write(struct file * file,
		const char __user * buf, size_t len, loff_t * ppos)
{
	int pos = *ppos;
	int first = pos >> PAGE_CACHE_SHIFT;
	int last = (len + PAGE_CACHE_SIZE-1) >> PAGE_CACHE_SHIFT;

	struct inode * f_inode = file->f_path.dentry->d_inode;
	struct btrfs_inode * inode;
	struct btrfs_key * location;
	ssize_t ret;

	ret = btrfs_acid_allow(f_inode);
	if (ret < 0) {
		BTRFS_SUB_DBG(ACCESS, "Refused access to PID %d\n", current->pid);
		return ret;
	}

	ret = do_sync_write(file, buf, len, ppos);
	if (ret < 0)
		goto out;

	inode = BTRFS_I(f_inode);
	if (!inode)
		return -EINVAL;
	location = &inode->location;

	BUG_ON(!inode->root->snap);
	btrfs_acid_log_write(inode->root->snap, location, first, last);
out:
	return ret;
}

static size_t __file_iov_count_bytes(const struct iovec * iov,
		unsigned long nr_segs)
{
	size_t count = 0;
	int i;

	if (!iov)
		return -EINVAL;

	for (i = 0; i < nr_segs; i ++)
		count += iov[i].iov_len;

	return count;
}


ssize_t
btrfs_acid_file_aio_read(struct kiocb *iocb, const struct iovec *iov,
		unsigned long nr_segs, loff_t pos)
{
	ssize_t read;
	loff_t first, last;
	struct inode * f_inode;
	struct btrfs_inode * inode;
	int ret;

	BTRFS_SUB_DBG(CALL, "");

	f_inode = fdentry(iocb->ki_filp)->d_inode;
	BUG_ON(!f_inode);

	ret = btrfs_acid_allow(f_inode);
	if (ret < 0) {
		BTRFS_SUB_DBG(ACCESS, "Refused access to PID %d\n", current->pid);
		return ret;
	}

	read = generic_file_aio_read(iocb, iov, nr_segs, pos);
	if (read == 0) {
		BTRFS_SUB_DBG(TX, "We just \"read\" 0 bytes. Should we log it?\n");
		goto out;
	}

	if (read < 0) {
		BTRFS_SUB_DBG(TX, "Error; should we log it?\n");
		goto out;
	}

	first = (pos >> PAGE_CACHE_SHIFT);
	last = (pos + __file_iov_count_bytes(iov, nr_segs)) >> PAGE_CACHE_SHIFT;

	inode = BTRFS_I(f_inode);

	btrfs_acid_log_read(inode->root->snap, &inode->location, first, last);

	out:
	return read;

}

ssize_t btrfs_acid_file_aio_write(struct kiocb *iocb,
				    const struct iovec *iov,
				    unsigned long nr_segs, loff_t pos)
{
	ssize_t written;
	loff_t first, last;
	struct inode * f_inode;
	struct btrfs_inode * inode;
	int ret;

	BTRFS_SUB_DBG(CALL, "");

	f_inode = fdentry(iocb->ki_filp)->d_inode;
	BUG_ON(!f_inode);

	ret = btrfs_acid_allow(f_inode);
	if (ret < 0) {
		BTRFS_SUB_DBG(ACCESS, "Refused access to PID %d\n", current->pid);
		return ret;
	}

	written = btrfs_file_aio_write(iocb, iov, nr_segs, pos);
	if (written == 0) {
		BTRFS_SUB_DBG(TX, "We just \"wrote\" 0 bytes. Should we log it?\n");
		goto out;
	}

	if (written < 0) {
		BTRFS_SUB_DBG(TX, "Error; should we log it?\n");
		goto out;
	}

	first = (pos >> PAGE_CACHE_SHIFT);
	last = (pos + __file_iov_count_bytes(iov, nr_segs)) >> PAGE_CACHE_SHIFT;

	inode = BTRFS_I(f_inode);

	btrfs_acid_log_write(inode->root->snap, &inode->location, first, last);

out:
	return written;
}

int btrfs_acid_getattr(struct vfsmount * mnt,
			 struct dentry * dentry, struct kstat * stat)
{
	int ret;
	struct inode * inode = dentry->d_inode;

	BTRFS_SUB_DBG(CALL, "");

	ret = btrfs_getattr(mnt, dentry, stat);
	BUG_ON(ret != 0); // at the moment, it always returns 0.

	ret = btrfs_acid_log_attr_get(inode);
	if (ret < 0)
		BTRFS_SUB_DBG(LOG, "attr_get logging returned an error\n");

	return 0;
}


/* Wrapper structs for all file system's required operations. */
/* from inode.c */
const struct inode_operations btrfs_acid_dir_inode_operations = {
	.getattr	= btrfs_acid_getattr,
	.lookup		= btrfs_lookup,
	.create		= btrfs_create,
	.unlink		= btrfs_unlink,
	.link		= btrfs_link,
	.mkdir		= btrfs_mkdir,
	.rmdir		= btrfs_rmdir,
	.rename		= btrfs_rename,
	.symlink	= btrfs_symlink,
	.setattr	= btrfs_setattr,
	.mknod		= btrfs_mknod,
	.setxattr	= btrfs_setxattr,
	.getxattr	= btrfs_getxattr,
	.listxattr	= btrfs_listxattr,
	.removexattr	= btrfs_removexattr,
	.permission	= btrfs_permission,
};

const struct inode_operations btrfs_acid_dir_ro_inode_operations = {
	.lookup		= btrfs_lookup,
	.permission	= btrfs_permission,
};

const struct file_operations btrfs_acid_dir_file_operations = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.readdir	= btrfs_real_readdir,
	.unlocked_ioctl	= btrfs_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= btrfs_ioctl,
#endif
	.release        = btrfs_release_file,
	.fsync		= btrfs_sync_file,
	.open		= btrfs_acid_file_open,
};

/*const struct address_space_operations btrfs_acid_aops = {
	.readpage	= btrfs_readpage,
	.writepage	= btrfs_writepage,
	.writepages	= btrfs_writepages,
	.readpages	= btrfs_readpages,
	.sync_page	= block_sync_page,
	.direct_IO	= btrfs_direct_IO,
	.invalidatepage = btrfs_invalidatepage,
	.releasepage	= btrfs_releasepage,
	.set_page_dirty	= btrfs_set_page_dirty,
	.error_remove_page = generic_error_remove_page,
};

const struct address_space_operations btrfs_acid_symlink_aops = {
	.readpage	= btrfs_readpage,
	.writepage	= btrfs_writepage,
	.invalidatepage = btrfs_invalidatepage,
	.releasepage	= btrfs_releasepage,
};*/

const struct inode_operations btrfs_acid_file_inode_operations = {
	.truncate	= btrfs_truncate,
	.getattr	= btrfs_acid_getattr,
	.setattr	= btrfs_setattr,
	.setxattr	= btrfs_setxattr,
	.getxattr	= btrfs_getxattr,
	.listxattr      = btrfs_listxattr,
	.removexattr	= btrfs_removexattr,
	.permission	= btrfs_permission,
	.fallocate	= btrfs_fallocate,
	.fiemap		= btrfs_fiemap,
};

const struct inode_operations btrfs_acid_special_inode_operations = {
	.getattr	= btrfs_acid_getattr,
	.setattr	= btrfs_setattr,
	.permission	= btrfs_permission,
	.setxattr	= btrfs_setxattr,
	.getxattr	= btrfs_getxattr,
	.listxattr	= btrfs_listxattr,
	.removexattr	= btrfs_removexattr,
};

const struct inode_operations btrfs_acid_symlink_inode_operations = {
	.readlink	= generic_readlink,
	.follow_link	= page_follow_link_light,
	.put_link	= page_put_link,
	.getattr	= btrfs_acid_getattr,
	.permission	= btrfs_permission,
	.setxattr	= btrfs_setxattr,
	.getxattr	= btrfs_getxattr,
	.listxattr	= btrfs_listxattr,
	.removexattr	= btrfs_removexattr,
};

const struct dentry_operations btrfs_acid_dentry_operations = {
	.d_delete	= btrfs_dentry_delete,
	.d_hash		= btrfs_acid_d_hash,
	.d_revalidate = btrfs_acid_d_revalidate,
};

/* from file.c */
const struct file_operations btrfs_acid_file_operations = {
	.llseek		= generic_file_llseek,
	.read		= do_sync_read,
	.write		= do_sync_write,
	.aio_read	= btrfs_acid_file_aio_read,
	.aio_write	= btrfs_acid_file_aio_write,
	.splice_read	= generic_file_splice_read,
	.mmap		= btrfs_file_mmap,
	.open		= btrfs_acid_file_open,
	.release	= btrfs_release_file,
	.fsync		= btrfs_sync_file,
	.unlocked_ioctl	= btrfs_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= btrfs_ioctl,
#endif
};

const struct vm_operations_struct btrfs_acid_file_vm_ops = {
	.fault		= filemap_fault,
	.page_mkwrite	= btrfs_page_mkwrite,
	.open = btrfs_acid_vm_open,
};


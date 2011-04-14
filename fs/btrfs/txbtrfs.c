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
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/kernel.h>
#include <linux/radix-tree.h>
#include <linux/namei.h>
#include <linux/fsnotify.h>
#include "ctree.h"
#include "btrfs_inode.h"
#include "transaction.h"
#include "disk-io.h"
#include "txbtrfs.h"
#include "txbtrfs-misc.h"
#include "hash.h"

/*
 * TxBtrfs aims at introducing Transactional Semantics into the file
 * system, using Btrfs as its coding base. (to be expanded)
 */

static int __snapshot_set_perms(struct inode * dir, struct dentry * dentry);
static struct dentry *
__snapshot_instantiate_dentry(struct dentry * dentry);
static struct btrfs_acid_snapshot *
__snapshot_add(struct btrfs_root * root, struct qstr * path);
static int __snapshot_create_path(struct btrfs_acid_ctl * ctl,
		struct qstr * path, pid_t pid);
static void __snapshot_destroy_path(struct qstr * path);

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
	char * new_ref_name;

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
		BTRFS_TX_DEBUG("Change root: ref name len <= 0\n");
		ref_name[0] = '\0';
	} else
		read_extent_buffer(leaf, ref_name,
				(unsigned long) (ref+1), ref_name_len);


	BTRFS_TX_DEBUG("Change root: ref: dirid = %llu, sequence = %llu, "
			"name = %.*s, namelen = %d\n",
			btrfs_root_ref_dirid(leaf, ref),
			btrfs_root_ref_sequence(leaf, ref),
			ref_name_len, ref_name, ref_name_len);

	if (ref_name_len + 4 < BTRFS_NAME_LEN)
	{
//		new_ref_name = (char *) kzalloc(ref_name_len + 4+1, GFP_KERNEL);
//		memcpy(new_ref_name, ref_name, ref_name_len);
//		memcpy(new_ref_name+ref_name_len, "_new", 4);
//		strcat(ref_name, "_new");
		BTRFS_TX_DEBUG("Change root: new_name = %s, new_name_len = %d\n",
				name, name_len);
//				new_ref_name, (int) strnlen(ref_name, BTRFS_NAME_LEN));

//		write_extent_buffer(leaf, new_ref_name, (unsigned long) (ref+1),
//				ref_name_len + 4);
//		btrfs_set_root_ref_name_len(leaf, ref, ref_name_len+4);
		write_extent_buffer(leaf, name, (unsigned long) (ref+1), name_len);
		btrfs_set_root_ref_name_len(leaf, ref, name_len);
		btrfs_mark_buffer_dirty(leaf);
	}

err_free_path:
//		btrfs_release_path(from_root->fs_info->tree_root, path);
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


	BTRFS_TX_DEBUG("Dir item: location key = [%llu %d %llu], name = %.*s\n",
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
/*	if (IS_ERR(di))
//		ret = PTR_ERR(di);
		goto out_err;

	if (!di || IS_ERR(di))
		goto out_err;
*/
	if (!di || IS_ERR(di))
	{
		BTRFS_TX_DEBUG("(get_root_by_name) dir item is NULL or ERR: %xll\n",
				(unsigned long long) di);
		goto out_err;
	}

	btrfs_dir_item_key_to_cpu(path->nodes[0], di, &location);
	btrfs_free_path(path);

	objective = btrfs_lookup_fs_root(root->fs_info, location.objectid);

/*out:
	btrfs_free_path(path);
	return ret;
out_err:
	location->objectid = 0;
	goto out;*/
out:
out_err:

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

	snap->root = sv;
	snap->gen = sv->root_item.generation;
	snap->location = key;
	snap->parent_ino = parent_ino;
	snap->path.name = name;
	snap->path.len = name_len;
	snap->path.hash = full_name_hash(name, name_len);
	snap->hash = btrfs_name_hash(name, name_len);

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
//	struct btrfs_root_item * ri, root_item;

	struct btrfs_acid_tx_subvol_item * ti, txsv_item;
	struct btrfs_disk_key txsv_disk_key;
	struct btrfs_key txsv_key;
	unsigned long txsv_parent_ino;
	int txsv_name_len;
	char * txsv_name;

	struct btrfs_acid_snapshot * txsv = NULL;

	u64 flags;
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

//		if (btrfs_key_type(&found_key) != BTRFS_ROOT_ITEM_KEY)
		if (btrfs_key_type(&found_key) != BTRFS_ACID_TX_SUBVOL_ITEM_KEY)
			goto loop_again;

		BTRFS_TX_DEBUG("Found tx subvol item: [%llu %d %llu]\n",
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
		read_extent_buffer(leaf, txsv_name, (unsigned long)(ti + 1),
					txsv_name_len);

		BTRFS_TX_DEBUG("Tx Subvol root key: [%llu %d %llu], name: %.*s, "
				"parent inode: %d\n",
				txsv_key.objectid, txsv_key.type, txsv_key.offset,
				txsv_name_len, txsv_name,
				txsv_parent_ino);


//		BTRFS_TX_DEBUG("Found root item: [%llu %d %llu]\n",
//				found_key.objectid, found_key.type, found_key.offset);
//
//		ri = btrfs_item_ptr(leaf, slot, struct btrfs_root_item);
//		if (IS_ERR_OR_NULL(ri))
//		{
//			// TODO: handle error condition.
//			BUG();
//		}
//		read_extent_buffer(leaf, &root_item,
//				(unsigned long) ri, sizeof(root_item));
//
//		flags = btrfs_root_flags(&root_item);
//		if (!(flags & BTRFS_ROOT_SUBVOL_ACID))
//			goto loop_again; /* not a tx subvol; loop again. */

		/* This key matches a transactional subvolume. Let's get its root. */
//		sv = btrfs_lookup_fs_root(tree_root->fs_info, found_key.objectid);
//		sv = btrfs_read_fs_root_no_name(tree_root->fs_info, &found_key);
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

		BTRFS_TX_DEBUG("Last key found is a Transactional Subvolume.\n");
		BTRFS_TX_DEBUG("TXSV: root %p key [%llu %d %llu] gen %d\n",
				txsv->root, txsv->location->objectid, txsv->location->type,
				txsv->location->offset, txsv->gen);
		BTRFS_TX_DEBUG("TXSV: parent ino: %d name: %.*s\n",
				txsv->parent_ino, txsv->path.len, txsv->path.name);

	}
	else
		BTRFS_TX_DEBUG("No Transactional Subvolume found.\n");

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
	BTRFS_TX_DEBUG("Subvolume flags = %llu\n", flags);
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

int btrfs_acid_d_hash(struct dentry * dentry, struct qstr * str)
{
	struct inode * inode = dentry->d_inode;
	struct btrfs_inode * our_inode = BTRFS_I(inode);
	struct btrfs_root * root = our_inode->root;
	struct btrfs_acid_ctl * ctl = &root->fs_info->acid_ctl;
	struct btrfs_acid_snapshot * snap = NULL;

//
//	char * default_to = "_snap";
//	char * final_name;
//	struct btrfs_root * str_root;
//	int parent_is_txsv = 0;

	/* At this point we should be in one of the following conditions:
	 * 	1) The access isn't to a TXSV and we should simply return, or
	 * 	2) Parent is not a TXSV but 'str' is a TXSV and we should deal with
	 * 	it accordingly, or
	 * 	3) Parent is a TX Snapshot and we should simply return.
	 */

	/* Basically, we should first check if the parent's root is a TX Snapshot,
	 * by checking its root item's flags. If it is flagged as as such, our work
	 * is done and we should return.
	 *
	 * If not, we'll simply check
	 */

	BTRFS_TX_DBG("HASH", "dentry name: %.*s, str: %.*s\n",
			dentry->d_name.len, dentry->d_name.name,
			str->len, str->name);

	down_read(&ctl->sv_sem);
	if (!ctl->sv) /* No TXSV, nothing to do. */
		goto ctl_up_read;

	BTRFS_TX_DBG("HASH", "str hash: %d, TXSV hash: %d\n",
			str->hash, ctl->sv->path.hash);

	if (ctl->sv->path.hash != str->hash)
		goto ctl_up_read; /* We are not looking for TXSV, therefore return. */

	BTRFS_TX_DBG("HASH", "Same name as TXSV\n");

	if (inode->i_ino != ctl->sv->parent_ino)
		goto ctl_up_read; /* Same name, different parent. Not the TXSV. */

	BTRFS_TX_DBG("HASH", "Same parent as TXSV\n");

	/* We are trying to access the TXSV, therefore let's find the current
	 * process' snapshot and map the access there. */
	down_read(&ctl->curr_snaps_sem);
	snap = radix_tree_lookup(&ctl->current_snapshots, current->pid);
	up_read(&ctl->curr_snaps_sem);
	if (!snap)
	{
		BTRFS_TX_DBG("HASH", "No Snapshot found for PID = %d\n", current->pid);
		goto ctl_up_read;
	}

	/* We've got the snapshot. Map the bastard. */
//	str = &snap->path; /* Is this really enough? Seems way too easy... */
//	kfree(str->name);
	str->name = kzalloc(snap->path.len, GFP_NOFS);
	BUG_ON(!str->name);
	memcpy(str->name, snap->path.name, snap->path.len);
	str->len = snap->path.len;
	str->hash = snap->path.hash;

	BTRFS_TX_DBG("HASH", "Mapped PID = %d to SNAP = %.*s\n",
			current->pid, str->len, str->name);

ctl_up_read:
	up_read(&ctl->sv_sem);
	return 0;
//
//	if (!btrfs_is_acid_subvol(root))
//	{
//		BTRFS_TX_DBG("HASH", "Parent is not the root of TXSV\n");
//		parent_is_txsv = 0;
//	} else
//	{
//		BTRFS_TX_DBG("HASH", "Parent IS the root of TXSV\n");
//		parent_is_txsv = 1;
//	}
//
//	str_root = get_root_by_name(our_inode, str);
//	if (!str_root)
//	{
//		BTRFS_TX_DEBUG("[hash] Root By Name returned an error.");
//		goto out;
//	}
//	print_key(&str_root->root_key);
//	if (btrfs_is_acid_subvol(str_root))
//		BTRFS_TX_DEBUG("[hash] Accessing a TX Subvolume.");
//	else
//		BTRFS_TX_DEBUG("[hash] Accessing a Non-TX Subvolume.");
//
//
//	final_name = kzalloc(str->len+5, GFP_KERNEL);
//	if (!final_name)
//		return -ENOMEM;
//
//	memcpy(final_name, str->name, str->len);
//	memcpy(final_name+str->len, default_to, 5);
//
//	str->name = final_name;
//	str->len += 5;
//	str->hash = full_name_hash(str->name, str->len);
//
//	BTRFS_TX_DEBUG("[hash] Changed name: %.*s, hash: %u\n",
//			str->len, str->name, str->hash);
//out:
//	return 0;
}

int btrfs_acid_d_revalidate(struct dentry * dentry, struct nameidata * nd)
{
	struct btrfs_root * root;
	struct btrfs_acid_ctl * ctl;

	BTRFS_TX_DBG("REVALIDATE", "Here we are.\n");

	if (!dentry)
		goto out;

	BTRFS_TX_DBG("REVALIDATE", "Here we are #2.\n");

	if (!dentry->d_inode)
	{
		BTRFS_TX_DBG("REVALIDATE", "dentry->d_inode == NULL\n");
		goto out;
	}

	BTRFS_TX_DBG("REVALIDATE", "Here we are. #3\n");

	if (!BTRFS_I(dentry->d_inode)->root)
	{
		BTRFS_TX_DBG("REVALIDATE", "dentry->d_inode->root == NULL\n");
		goto out;
	}

	BTRFS_TX_DBG("REVALIDATE", "Here we are. #4\n");

	root = BTRFS_I(dentry->d_inode)->root;

	if (!root->fs_info)
	{
		BTRFS_TX_DBG("REVALIDATE", "root->fs_info == NULL\n");
		goto out;
	}

	BTRFS_TX_DBG("REVALIDATE", "Here we are. #5\n");

	ctl = &root->fs_info->acid_ctl;

	BTRFS_TX_DBG("REVALIDATE", "name: %.*s\n",
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
			BTRFS_TX_DBG("REVALIDATE", "Dropped it.\n");
		}
	}

out_up_read:
	up_read(&ctl->sv_sem);

out:
	return dentry;
}


int btrfs_acid_tx_start(struct file * file)
{
	int ret = 0;
	struct dentry * sv_dentry;
	struct btrfs_root * root;
	struct btrfs_acid_snapshot * snap = NULL;
	pid_t curr_pid = current->pid;

	sv_dentry = dget(fdentry(file));

	BTRFS_TX_DBG("TXSTART", "Starting transaction on %.*s for process %d\n",
			sv_dentry->d_name.len, sv_dentry->d_name.name, curr_pid);

	/* First of all, we must check if 'sv_dentry' actually is a valid
	 * transactional subvolume. Not only it must have the right flags, it must
	 * be the one set as the TX SV in fs_info's acid_ctl.
	 */
	root = BTRFS_I(sv_dentry->d_inode)->root;
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

	BTRFS_TX_DBG("TXSTART", "Transaction %d mapped onto %.*s\n",
			snap->owner_pid, snap->path.len, snap->path.name);

	/* The snapshot is created, added to the tree, everything is either
	 * fine or not. Anyway, we have nothing else to do, so we return. */

out:
	dput(sv_dentry);
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
//	struct btrfs_path * path;
//	struct btrfs_key search_key;
//	struct extent_buffer * leaf;
//	struct btrfs_root_ref * ref;
//	char ref_name[BTRFS_NAME_LEN];
//	int ref_name_len;
	struct btrfs_trans_handle * trans;

	BTRFS_TX_DEBUG("Change root: fd = %lld to fd = %lld\n",
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

//	memset(from_name, 0, sizeof(*from_name) * from_dentry->d_name.len);
//	memset(to_name, 0, sizeof(*to_name) * to_dentry->d_name.len);

	memcpy(from_name, from_dentry->d_name.name, from_dentry->d_name.len);
	memcpy(to_name, to_dentry->d_name.name, to_dentry->d_name.len);

	new_name_len = from_name_len + 4;
	new_name = (char *) kzalloc(new_name_len+1, GFP_KERNEL);
	memcpy(new_name, from_name, from_name_len);
	memcpy(new_name+from_name_len, "_new", 4);

	BTRFS_TX_DEBUG("Change root: '%s' to '%.*s'\n", from_name,
			new_name_len, new_name);

	from_inode = BTRFS_I(from_dentry->d_inode);
	to_inode = BTRFS_I(to_dentry->d_inode);

	from_location = &from_inode->location;
	to_location = &to_inode->location;

	BTRFS_TX_DEBUG("Change root: 'from' key = [%lld %d %lld], "
			"'to' key = [%lld %d %lld]\n",
			from_location->objectid, from_location->type, from_location->offset,
			to_location->objectid, to_location->type, to_location->offset);

	from_root = from_inode->root;
	to_root = to_inode->root;

	from_root_key = &from_inode->root->root_key;
	to_root_key = &to_inode->root->root_key;

	BTRFS_TX_DEBUG("Change root: 'from' root key = [%lld %d %lld], "
			"'to' root key = [%lld %d %lld]\n",
			from_root_key->objectid, from_root_key->type, from_root_key->offset,
			to_root_key->objectid, to_root_key->type, to_root_key->offset);

	// the whole search process, excluding everything after 'btrfs_search_slot'
	// could have been done using 'btrfs_find_root_ref'.

	trans = btrfs_start_transaction(from_root->fs_info->tree_root, 2);
	btrfs_record_root_in_trans(trans, from_root->fs_info->tree_root);

	/*
	change_tree_root_ref_name(trans, from_root->fs_info->tree_root,
			BTRFS_FS_TREE_OBJECTID, BTRFS_ROOT_REF_KEY,
			from_root_key->objectid, new_name, new_name_len);
	change_tree_root_ref_name(trans, from_root->fs_info->tree_root,
			from_root_key->objectid, BTRFS_ROOT_BACKREF_KEY,
			BTRFS_FS_TREE_OBJECTID, new_name, new_name_len);
	*/

	get_fs_root_dir_item(trans, from_file);


//	change_fs_root_dir_item(trans, from_root->fs_info->fs_root,)

//
//	search_key.objectid = from_root_key->objectid;
//	search_key.type = BTRFS_ROOT_BACKREF_KEY;
//	search_key.offset = BTRFS_FS_TREE_OBJECTID;
//
//	ret = btrfs_search_slot(NULL, from_root->fs_info->tree_root, &search_key,
//			path, 0, 0);
//	BUG_ON(ret < 0);
//	if (ret != 0)
//	{
//		ret = -ENOENT;
//		goto err_free_path;
//	}
//
//	leaf = path->nodes[0];
//	ref = btrfs_item_ptr(leaf, path->slots[0], struct btrfs_root_ref);
//	ref_name_len = btrfs_root_ref_name_len(leaf, ref);
//	if (ref_name_len <= 0)
//	{
//		BTRFS_TX_DEBUG("Change root: ref name len <= 0\n");
//		ref_name[0] = '\0';
//	} else
//		read_extent_buffer(leaf, ref_name,
//				(unsigned long) (ref+1), ref_name_len);
//
//	BTRFS_TX_DEBUG("Change root: ref: dirid = %llu, sequence = %llu, "
//			"name = %.*s\n",
//			btrfs_root_ref_dirid(leaf, ref),
//			btrfs_root_ref_sequence(leaf, ref),
//			ref_name_len, ref_name);
//
//	if (ref_name_len + 4 < BTRFS_NAME_LEN)
//	{
//		strcat(ref_name, "_new");
//		write_extent_buffer(leaf, ref_name, (unsigned long) (ref+1),
//				ref_name_len + 4);
//		btrfs_set_root_ref_name_len(leaf, ref, ref_name_len+4);
//		btrfs_mark_buffer_dirty(leaf);
//	}

	btrfs_commit_transaction(trans, from_root->fs_info->tree_root);

//err_free_path:
//	btrfs_free_path(path);
	kfree(to_name);
err_free_from_name:
	kfree(from_name);
err_fput:
	fput(to_file);
	fput(from_file);

	return ret;
}

int btrfs_insert_snapshot_item(struct btrfs_trans_handle * trans,
		struct btrfs_root * tree_root, struct btrfs_key * src_key,
		struct btrfs_key * snap_key)
{
	struct btrfs_acid_snapshot_item * item;
	struct btrfs_key key;
	int ret = 0;
	struct btrfs_root * snap_root;

	if (!trans || !tree_root || !src_key || !snap_key)
		return -EINVAL;

	item = kzalloc(sizeof(*item), GFP_KERNEL);
	if (!item)
		return -ENOMEM;

	btrfs_cpu_key_to_disk(&item->snap_key, snap_key);
	btrfs_cpu_key_to_disk(&item->src_key, src_key);
	item->owner_pid = cpu_to_le64(current->pid);

	key.objectid = src_key->objectid;
	key.type = BTRFS_ACID_SNAPSHOT_ITEM_KEY;
	key.offset = snap_key->objectid;

	ret = btrfs_insert_item(trans, tree_root, &key, item, sizeof(*item));
	BUG_ON(ret);

	/* just checks if the inserted root item actually allows us to get to
	 * the tree */
//	snap_root = btrfs_read_fs_root_no_name(tree_root->fs_info, &key);
//	BUG_ON(IS_ERR(snap_root));

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

	BTRFS_TX_DEBUG("inode: ino = %lu, file: %.*s\n",
			inode->i_ino, fdentry->d_name.len, fdentry->d_name.name);
	print_key(&our_inode->location);



	return 0;
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

	BTRFS_TX_DBG("CREATE-SNAPSHOT", "Creating Snapshot for PID = %d\n",
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
	BTRFS_TX_DBG("CREATE-SNAPSHOT",
			"Snapshot path: name = %.*s, len = %d, hash = %d\n",
			snap_path.len, snap_path.name, snap_path.len, snap_path.hash);

	mutex_lock_nested(&dir->i_mutex, I_MUTEX_PARENT);

	pending->dentry = lookup_one_len(snap_path.name,
			txsv_dentry->d_parent, snap_path.len);
	if (IS_ERR(pending->dentry))
	{
		snap = pending->dentry;
		goto out_destroy_path;
	}
	BTRFS_TX_DBG("CREATE-SNAPSHOT", "Pending dentry: name = %.*s, hash = %d\n",
			pending->dentry->d_name.len, pending->dentry->d_name.name,
			pending->dentry->d_name.hash);

	if (pending->dentry->d_inode)
	{
		snap = ERR_PTR(-EEXIST);
		goto out_destroy_path;
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
		snap = trans;
		goto out_destroy_path;
	}

	ret = btrfs_snap_reserve_metadata(trans, pending);
	BUG_ON(ret);

	list_add(&pending->list, &trans->transaction->pending_snapshots);

	ret = btrfs_commit_transaction(trans, src_root->fs_info->extent_root);
	BUG_ON(ret);

	BTRFS_TX_DBG("CREATE-SNAPSHOT", "Transaction committed.\n");

	ret = pending->error;
	if (ret)
		goto out_destroy_path;

	btrfs_orphan_cleanup(pending->snap);

	/* Adds the snapshot to the snapshot's tree */
	snap = __snapshot_add(pending->snap, &snap_path);
	BTRFS_TX_DBG("CREATE-SNAPSHOT", "Snapshot key [%llu %d %llu]\n",
			pending->snap->root_key.objectid,
			pending->snap->root_key.type,
			pending->snap->root_key.offset);

	snap_dentry = __snapshot_instantiate_dentry(pending->dentry);
	if (!snap_dentry || IS_ERR(snap_dentry))
	{
		// TODO: Do error handling.
		BTRFS_TX_DBG("CREATE-SNAPSHOT", "This is going to blow!\n");
		goto out;
	}
	__snapshot_set_perms(dir, snap_dentry);

//	pending->snap->owner_pid = current->pid;

//	if (IS_ERR(snap))
//		goto out_destroy_path;

//	up_read(&src_root->fs_info->subvol_sem);

out_destroy_path:
	__snapshot_destroy_path(&snap_path);

out_free_pending:

	if (ret)
		snap = ERR_PTR(ret);
	else
		fsnotify_mkdir(dir, pending->dentry);

	d_drop(pending->dentry);
	dput(pending->dentry);

	kfree(pending);
	mutex_unlock(&dir->i_mutex);
out:
	BTRFS_TX_DBG("CREATE-SNAPSHOT", "Returning\n");
	return snap;
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


	ret = btrfs_acid_create_snapshot(fdentry(src_file));

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

	BTRFS_TX_DEBUG("dentry name: %.*s\n",
			dentry->d_name.len, dentry->d_name.name);
	BTRFS_TX_DEBUG("parent name: %.*s, inode: %u\n",
			dentry->d_parent->d_name.len, dentry->d_parent->d_name.name,
			dentry->d_parent->d_inode->i_ino);

	BTRFS_TX_DEBUG("dentry name hash: %u, our hash: %u\n",
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

	BTRFS_TX_DEBUG("Subvol initial flags: %llu\n", initial_flags);

	if (initial_flags & BTRFS_ROOT_SUBVOL_ACID)
		goto out_up_write; /* subvolume already flagged as transactional. */

	final_flags |= BTRFS_ROOT_SUBVOL_ACID;

	BTRFS_TX_DEBUG("Subvol final flags: %llu\n", final_flags);

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
		BTRFS_TX_DEBUG("Resetting Subvol flags\n");
		btrfs_set_root_flags(&sub_root->root_item, initial_flags);
	}

out_up_write:
	up_write(&sub_root->fs_info->subvol_sem);
out_up_write_sv:
	up_write(&sub_root->fs_info->acid_ctl.sv_sem);
	return ret;
}

int btrfs_acid_init(struct btrfs_fs_info * fs_info)
{
	struct btrfs_acid_ctl * ctl;
	struct btrfs_acid_snapshot * txsv;
	struct btrfs_acid_snapshot * current_snapshot;

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

out:
	return 0;
}

static int __snapshot_set_perms(struct inode * dir, struct dentry * dentry)
{
	struct iattr attrs;
	struct inode * inode;

	attrs.ia_uid = current_uid();
	attrs.ia_gid = current_gid();

	attrs.ia_mode = S_IFDIR | S_IRWXU | S_IRWXG | S_IRWXO;
	attrs.ia_valid = ATTR_MODE | ATTR_UID | ATTR_GID;

	BTRFS_TX_DBG("SNAPSHOT-SET-PERMS",
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
		dentry = PTR_ERR(inode);
		goto fail;
	}
	BUG_ON(!inode);
	d_instantiate(dentry, inode);

fail:
	return dentry;
}

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

	snap->location = &root->root_key;
	snap->root = root;
	snap->owner_pid = current->pid;

	/* Create a snapshot name and hash for dcache, and also create an hash
	 * for our own comparing purposes.
	 */
	/* snapshot path creation must happen back in btrfs_acid_create_snapshot
	 * so we can create a dentry and use it during the pending snapshot
	 * creation.
	 */
//	__snapshot_create_path(ctl, &snap->path, snap->owner_pid);
//	memcpy(&snap->path, path, sizeof(*path));
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
	final_name_len = tmp_name_len + ctl->sv->path.len;
	final_name = kzalloc(sizeof(*final_name) * final_name_len, GFP_NOFS);
	if (!final_name)
	{
		ret = -ENOMEM;
		goto out;
	}

	memcpy(final_name, ctl->sv->path.name, ctl->sv->path.len);
	memcpy(final_name+ctl->sv->path.len, tmp_name, tmp_name_len);

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

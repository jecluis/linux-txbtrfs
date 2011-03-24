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
#include "ctree.h"
#include "btrfs_inode.h"
#include "transaction.h"
#include "disk-io.h"
#include "txbtrfs.h"

int btrfs_acid_tx_start(struct file * file)
{
//	printk(KERN_DEBUG "[debug] Btrfs ACID Tx Start\n");
//	printk(KERN_WARNING "[warning] Btrfs ACID Tx Start\n");
//	printk(KERN_NOTICE "[notice] Btrfs ACID Tx Start\n");
//	printk(KERN_INFO "[info]ÊBtrfs ACID Tx Start\n");
	BTRFS_TX_DEBUG("TX_START pid = %d\n", current->pid);

	return 0;
}

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

int btrfs_acid_create_snapshot(struct file * file,
		struct btrfs_ioctl_acid_create_snapshot_args * args)
{
	struct file * src_file;
	struct btrfs_root * src_root;
	struct btrfs_pending_snapshot * pending;
	struct btrfs_trans_handle * trans;
	int ret;

	if (!args)
		return -EINVAL;

	src_file = fget(args->src_fd);
	if (!src_file)
		return -EINVAL;

	src_root = BTRFS_I(src_file->f_path.dentry->d_inode)->root;

	pending = kzalloc(sizeof(*pending), GFP_KERNEL);
	if (!pending)
	{
		ret = -ENOMEM;
		goto err_put_file;
	}

	btrfs_init_block_rsv(&pending->block_rsv);
	pending->acid_tx = 1;
	pending->root = src_root;

	/* two items: 1 root item, 1 snapshot item */
	trans = btrfs_start_transaction(src_root->fs_info->extent_root, 2);
	if (IS_ERR(trans))
	{
		ret = PTR_ERR(trans);
		goto err_free_pending;
	}

	ret = btrfs_snap_reserve_metadata(trans, pending);
	BUG_ON(ret);

	list_add(&pending->list, &trans->transaction->pending_snapshots);

	ret = btrfs_commit_transaction(trans, src_root->fs_info->extent_root);
	BUG_ON(ret);

	ret = pending->error;
	if (ret)
		goto err_free_pending;

	btrfs_orphan_cleanup(pending->snap);

err_free_pending:
	kfree(pending);
err_put_file:
	fput(src_file);

	return ret;
}


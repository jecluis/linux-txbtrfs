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

static void print_key(struct btrfs_key * key)
{
	printk(KERN_DEBUG "key [%llu %d %llu]\n",
			key->objectid, key->type, key->offset);

}

static int is_acid_subvol(struct btrfs_root * root)
{
	u64 flags;

	down_write(&root->fs_info->subvol_sem);
	flags = btrfs_root_flags(&root->root_item);
	up_write(&root->fs_info->subvol_sem);

	BTRFS_TX_DEBUG("Subvolume flags = %llu\n", flags);

	return (flags & BTRFS_ROOT_SUBVOL_ACID);
}

/* based on btrfs_inode_by_name */
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

int btrfs_acid_d_hash(struct dentry * dentry, struct qstr * str)
{
	struct inode * inode = dentry->d_inode;
	struct btrfs_inode * our_inode = BTRFS_I(inode);
	struct btrfs_root * root = our_inode->root;
	char * default_to = "_snap";
	char * final_name;
	struct btrfs_root * str_root;

	BTRFS_TX_DEBUG("[hash] dentry name: %.*s, str: %.*s\n",
			dentry->d_name.len, dentry->d_name.name,
			str->len, str->name);

	if (!is_acid_subvol(root))
	{
		BTRFS_TX_DEBUG("[hash] Parent not TX Subvolume. Keeping hash.");
//		return 0;
	} else
		BTRFS_TX_DEBUG("[hash] Parent is a TX Subvolume. Changing hash.");

	str_root = get_root_by_name(our_inode, str);
	if (!str_root)
	{
		BTRFS_TX_DEBUG("[hash] Root By Name returned an error.");
		goto out;
	}
	print_key(&str_root->root_key);
	if (is_acid_subvol(str_root))
		BTRFS_TX_DEBUG("[hash] Accessing a TX Subvolume.");
	else
		BTRFS_TX_DEBUG("[hash] Accessing a Non-TX Subvolume.");


	final_name = kzalloc(str->len+5, GFP_KERNEL);
	if (!final_name)
		return -ENOMEM;

	memcpy(final_name, str->name, str->len);
	memcpy(final_name+str->len, default_to, 5);

	str->name = final_name;
	str->len += 5;
	str->hash = full_name_hash(str->name, str->len);

	BTRFS_TX_DEBUG("[hash] Changed name: %.*s, hash: %u\n",
			str->len, str->name, str->hash);
out:
	return 0;
}


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

struct file* file_open(const char* path, int flags, int rights) {
    struct file* filp = NULL;
    mm_segment_t oldfs;
    int err = 0;

    oldfs = get_fs();
    set_fs(get_ds());
    filp = filp_open(path, flags, rights);
    set_fs(oldfs);
    if(IS_ERR(filp)) {
    	err = PTR_ERR(filp);
    	return NULL;
    }
    return filp;
}

void file_close(struct file* file) {
    filp_close(file, NULL);
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

int btrfs_acid_create_snapshot(struct file * file,
		struct btrfs_ioctl_acid_create_snapshot_args * args)
{
	struct file * src_file;
	struct btrfs_root * src_root;
	struct btrfs_pending_snapshot * pending;
	struct btrfs_trans_handle * trans;
	int ret = 0;
	char * filename = "/home/dweller/txbtrfs.mnt/S1";
	struct file * f;

	if (!args)
		return -EINVAL;

	f = file_open(filename, 0, O_RDONLY);
	file_close(f);

	if (1)
		return 0;

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

	down_read(&src_root->fs_info->subvol_sem);

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

	up_read(&src_root->fs_info->subvol_sem);

err_free_pending:
	kfree(pending);
err_put_file:
	fput(src_file);

	return ret;
}

int btrfs_acid_subvol_flags(struct file * file,
		struct btrfs_ioctl_acid_subvol_flags_args * args)
{
	int ret = 0;
	struct inode * inode;
	struct btrfs_inode * sub_inode;
	struct btrfs_root * sub_root;
	u64 initial_flags, final_flags;
	struct btrfs_trans_handle * trans;

	if (!args)
		return -EINVAL;

	/* TODO: check for permission to do this */

	inode = fdentry(file)->d_inode;

	if (inode->i_ino != BTRFS_FIRST_FREE_OBJECTID)
		return -EINVAL;

	sub_inode = BTRFS_I(inode);
	sub_root = sub_inode->root;

	down_write(&sub_root->fs_info->subvol_sem);
	initial_flags = btrfs_root_flags(&sub_root->root_item);
	final_flags = initial_flags;

	BTRFS_TX_DEBUG("Subvol initial flags: %llu\n", initial_flags);

	if (args->set)
		final_flags |= BTRFS_ROOT_SUBVOL_ACID;
	else
		final_flags &= ~BTRFS_ROOT_SUBVOL_ACID;

	BTRFS_TX_DEBUG("Subvol final flags: %llu\n", final_flags);

	btrfs_set_root_flags(&sub_root->root_item, final_flags);

	trans = btrfs_start_transaction(sub_root, 1);
	if (IS_ERR(trans))
	{
		ret = PTR_ERR(trans);
		goto out_reset_flags;
	}

	ret = btrfs_update_root(trans, sub_root->fs_info->tree_root,
			&sub_root->root_key, &sub_root->root_item);

	btrfs_commit_transaction(trans, sub_root);

out_reset_flags:
	if (ret)
	{
		BTRFS_TX_DEBUG("Resetting Subvol flags\n");
		btrfs_set_root_flags(&sub_root->root_item, initial_flags);
	}

	up_write(&sub_root->fs_info->subvol_sem);
	return ret;
}

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
#include <linux/pagemap.h>
#include "ctree.h"
#include "btrfs_inode.h"
#include "txbtrfs.h"
#include "txbtrfs-log.h"

/* Static methods */
/* creation methods */
static struct btrfs_acid_log_mmap *
__log_create_mmap(struct btrfs_key * location, struct qstr * name,
		pgoff_t start, pgoff_t end, pgprot_t prot, unsigned long flags);
static struct btrfs_acid_log_permission *
__log_create_permission(struct btrfs_key * location, int mask);
static struct btrfs_acid_log_truncate *
__log_create_truncate(struct btrfs_key * location, loff_t size);
static struct btrfs_acid_log_xattr *
__log_create_xattr(struct btrfs_key * location, struct qstr * name,
		const char * attr_name, const void * value, size_t size, int flags);
static struct btrfs_acid_log_mknod *
__log_create_mknod(struct btrfs_key * parent_location, struct qstr * name,
		struct btrfs_key * location, int mode, dev_t rdev);
static struct btrfs_acid_log_symlink *
__log_create_symlink(struct btrfs_key * parent_location, struct qstr * name,
		struct btrfs_key * location, const char * symname);
static struct btrfs_acid_log_rename *
__log_create_rename(struct btrfs_key * old_key, struct qstr * old_name,
		struct btrfs_key * new_key, struct qstr * new_name);
static struct btrfs_acid_log_rmdir *
__log_create_rmdir(struct btrfs_key * key, struct qstr * name);
static struct btrfs_acid_log_mkdir *
__log_create_mkdir(struct btrfs_key * key, struct qstr * name, int mode);
static struct btrfs_acid_log_link *
__log_create_link(struct btrfs_key * old_key, struct qstr * old_name,
		struct btrfs_key * new_key, struct qstr * new_name);
static struct btrfs_acid_log_unlink *
__log_create_unlink(struct btrfs_key * inode_key, struct qstr * d_name);
static struct btrfs_acid_log_create *
__log_create_create(struct btrfs_key * inode_key,
		struct qstr * d_name, int mode);
//static struct btrfs_acid_log_attr_rw *
//__log_create_attr_rw(unsigned int flags);
static struct btrfs_acid_log_attr_rw *
__log_create_attr_rw(struct dentry * dentry, unsigned int flags);
static struct btrfs_acid_log_rw *
__log_create_rw(pgoff_t first, pgoff_t last);
static struct btrfs_acid_log_entry *
__log_create_entry(struct btrfs_acid_snapshot * snap,
		struct btrfs_key * location,
		size_t size, void * data, u32 type);

/* destruction methods */
static void
__log_destroy_create(struct btrfs_acid_log_create * entry);
static void
__log_destroy_unlink(struct btrfs_acid_log_unlink * entry);
static void __log_destroy_link(struct btrfs_acid_log_link * entry);
static void
__log_destroy_mkdir(struct btrfs_acid_log_mkdir * entry);
static void __log_destroy_rmdir(struct btrfs_acid_log_rmdir * entry);
static void __log_destroy_rename(struct btrfs_acid_log_rename * entry);
static void __log_destroy_symlink(struct btrfs_acid_log_symlink * entry);
static void __log_destroy_attr_rw(struct btrfs_acid_log_attr_rw * entry);
static void __log_destroy_mknod(struct btrfs_acid_log_mknod * entry);
static void __log_destroy_xattr(struct btrfs_acid_log_xattr * entry);
static void __log_destroy_mmap(struct btrfs_acid_log_mmap * entry);

/*
 * Adds a 'read' entry to the read-set.
 */
int btrfs_acid_log_read(struct btrfs_acid_snapshot * snap,
		struct btrfs_key * location, pgoff_t first, pgoff_t last)
{
	int ret = 0;
	struct btrfs_acid_log_rw * rw_entry;
	struct btrfs_acid_log_entry * log_entry;

	BTRFS_SUB_DBG(LOG, "READ: inode [%llu %d %llu] "
				"first page = %d, last page = %d\n",
				location->objectid, location->type, location->offset,
				first, last);


	rw_entry = __log_create_rw(first, last);
	if (IS_ERR(rw_entry))
		return PTR_ERR(rw_entry);

	log_entry = __log_create_entry(snap, location,
			sizeof(*rw_entry), rw_entry, BTRFS_ACID_LOG_READ);
	if (IS_ERR(log_entry))
	{
		ret = PTR_ERR(log_entry);
		goto err_destroy_rw_entry;
	}

	BTRFS_SUB_DBG(LOG, "READ: Adding to write-log\n");
	list_add(&log_entry->list, &snap->read_log);

	return ret;

err_destroy_rw_entry:
	kfree(rw_entry);
	return ret;
}

/*
 * Adds a 'write' entry to the write-set.
 */
int btrfs_acid_log_write(struct btrfs_acid_snapshot * snap,
		struct btrfs_key * location, pgoff_t first, pgoff_t last)
{
	int ret = 0;
	struct btrfs_acid_log_rw * rw_entry;
	struct btrfs_acid_log_entry * log_entry;

	/*BTRFS_SUB_DBG(LOG, "WRITE: inode [%llu %d %llu] "
				"first page = %d, last page = %d\n",
				location->objectid, location->type, location->offset,
				first, last);*/


	rw_entry = __log_create_rw(first, last);
	if (IS_ERR(rw_entry))
		return PTR_ERR(rw_entry);

	log_entry = __log_create_entry(snap, location,
			sizeof(*rw_entry), rw_entry, BTRFS_ACID_LOG_WRITE);
	if (IS_ERR(log_entry)) {
		ret = PTR_ERR(log_entry);
		goto err_destroy_rw_entry;
	}

	BTRFS_SUB_DBG(LOG, "WRITE: Adding to write-log\n");
	list_add(&log_entry->list, &snap->write_log);

	return ret;

err_destroy_rw_entry:
	kfree(rw_entry);
	return ret;
}

/* Adds an entry to the log referring to a 'get attrs' issued on an inode. */
//int btrfs_acid_log_getattr(struct inode * inode)
int btrfs_acid_log_getattr(struct dentry * dentry)
{
	struct btrfs_acid_snapshot * snap;
	struct btrfs_inode * our_inode;
	struct btrfs_acid_log_attr_rw * attr_rw_entry;
	struct btrfs_acid_log_entry * log_entry;

	if (unlikely(!dentry || !dentry->d_inode))
		return -EINVAL;

//	our_inode = BTRFS_I(inode);
	our_inode = BTRFS_I(dentry->d_inode);
	snap = our_inode->root->snap;

	if (!snap)
		return -ENOTSUPP;

//	attr_rw_entry = __log_create_attr_rw(0);
	attr_rw_entry = __log_create_attr_rw(dentry, 0);
	if (IS_ERR(attr_rw_entry))
		return PTR_ERR(attr_rw_entry);

	log_entry = __log_create_entry(snap, &our_inode->location,
			sizeof(*attr_rw_entry), attr_rw_entry, BTRFS_ACID_LOG_ATTR_GET);
	if (IS_ERR(log_entry)) {
		kfree(attr_rw_entry);
		return PTR_ERR(log_entry);
	}

	BTRFS_SUB_DBG(LOG, "GET-ATTR: Adding to read-log\n");
	list_add(&log_entry->list, &snap->read_log);

	return 0;
}

/* Adds an entry to the log referring to a 'readdir'/'getdents' issued
 * on directory entry (although perceived as an inode). */
int btrfs_acid_log_readdir(struct inode * inode)
{
	struct btrfs_acid_snapshot * snap;
	struct btrfs_inode * our_inode;
	struct btrfs_acid_log_entry * log_entry;

	if (unlikely(!inode))
		return -EINVAL;

	our_inode = BTRFS_I(inode);
	snap = our_inode->root->snap;
	if (!snap)
		return -ENOTSUPP;

	log_entry = __log_create_entry(snap, &our_inode->location,
			0, NULL, BTRFS_ACID_LOG_READDIR);
	if (IS_ERR(log_entry))
		return PTR_ERR(log_entry);

	BTRFS_SUB_DBG(LOG, "READDIR: Adding to read-log\n");
	list_add(&log_entry->list, &snap->read_log);

	return 0;
}

/* Adds an entry to the log referring to a 'creat()'. */
int btrfs_acid_log_create(struct inode * dir, struct dentry * dentry, int mode)
{
	struct btrfs_acid_log_entry * log_entry;
	struct btrfs_acid_log_create * log_entry_create;
	struct btrfs_acid_snapshot * snap;
	struct btrfs_root * root;
	struct btrfs_inode * our_inode, * our_parent_inode;
	struct qstr * d_name;

	if (!dir || !dentry || !dentry->d_inode)
		return -EINVAL;

	our_parent_inode = BTRFS_I(dir);
	our_inode = BTRFS_I(dentry->d_inode);
	root = our_parent_inode->root;
	snap = root->snap;
	d_name = &dentry->d_name;

	log_entry_create =
			__log_create_create(&our_inode->location, d_name, mode);
	if (IS_ERR(log_entry_create))
		return PTR_ERR(log_entry_create);

	log_entry = __log_create_entry(snap, &our_parent_inode->location,
			sizeof(*log_entry_create), log_entry_create, BTRFS_ACID_LOG_CREATE);
	if (IS_ERR(log_entry)) {
		__log_destroy_create(log_entry_create);
		return PTR_ERR(log_entry);
	}

	BTRFS_SUB_DBG(LOG, "CREATE: Adding to write-log\n");
	list_add(&log_entry->list, &snap->write_log);


	return 0;
}

int btrfs_acid_log_unlink(struct inode * dir, struct dentry * dentry)
{
	struct btrfs_acid_log_entry * log_entry;
	struct btrfs_acid_log_unlink * log_entry_unlink;
	struct btrfs_acid_snapshot * snap;
	struct btrfs_inode * our_inode, * parent_inode;
	struct qstr * d_name;

	if (!dir || !dentry || !dentry->d_inode)
		return -EINVAL;

	parent_inode = BTRFS_I(dir);
	our_inode = BTRFS_I(dentry->d_inode);
	snap = parent_inode->root->snap;
	d_name = &dentry->d_name;

	log_entry_unlink = __log_create_unlink(&our_inode->location, d_name);
	if (IS_ERR(log_entry_unlink))
		return PTR_ERR(log_entry_unlink);

	log_entry = __log_create_entry(snap, &parent_inode->location,
			sizeof(*log_entry_unlink), log_entry_unlink, BTRFS_ACID_LOG_UNLINK);
	if (IS_ERR(log_entry)) {
		__log_destroy_unlink(log_entry_unlink);
		return PTR_ERR(log_entry);
	}

	BTRFS_SUB_DBG(LOG, "UNLINK: Adding to write-log\n");
	list_add(&log_entry->list, &snap->write_log);

	return 0;
}

int btrfs_acid_log_link(struct dentry * old_dentry, struct inode * dir,
		struct dentry * new_dentry)
{
	struct btrfs_acid_log_entry * log_entry;
	struct btrfs_acid_log_link * log_entry_link;
	struct btrfs_acid_snapshot * snap;
	struct btrfs_inode * new_inode, * parent_inode, * old_inode;

	if (!old_dentry || !dir || !new_dentry) {
		BTRFS_SUB_DBG(LOG, "ERROR: LINK: NULL params\n");
		return -EINVAL;
	}

	parent_inode = BTRFS_I(dir);
	old_inode = BTRFS_I(old_dentry->d_inode);
	new_inode = BTRFS_I(new_dentry->d_inode);
	snap = parent_inode->root->snap;

	log_entry_link = __log_create_link(&old_inode->location,
			&old_dentry->d_name, &new_inode->location, &new_dentry->d_name);
	if (IS_ERR(log_entry_link))
		return PTR_ERR(log_entry_link);

	log_entry = __log_create_entry(snap, &parent_inode->location,
			sizeof(*log_entry_link), log_entry_link, BTRFS_ACID_LOG_LINK);
	if (IS_ERR(log_entry)) {
		__log_destroy_link(log_entry_link);
		return PTR_ERR(log_entry);
	}

	BTRFS_SUB_DBG(LOG, "LINK: Adding to write-log\n");
	list_add(&log_entry->list, &snap->write_log);

	return 0;
}

int btrfs_acid_log_mkdir(struct inode * dir, struct dentry * dentry, int mode)
{
	struct btrfs_acid_snapshot * snap;
	struct btrfs_inode * dir_inode, * dentry_inode;
	struct qstr * qstr;
	struct btrfs_acid_log_entry * log_entry;
	struct btrfs_acid_log_mkdir * log_entry_mkdir;

	if (!dir || !dentry || !dentry->d_inode)
		return -EINVAL;

	dir_inode = BTRFS_I(dir);
	dentry_inode = BTRFS_I(dentry->d_inode);
	qstr = &dentry->d_name;
	snap = dir_inode->root->snap;

	log_entry_mkdir =
			__log_create_mkdir(&dentry_inode->location, qstr, mode);
	if (IS_ERR(log_entry_mkdir))
		return PTR_ERR(log_entry_mkdir);

	log_entry = __log_create_entry(snap, &dir_inode->location,
			sizeof(*log_entry_mkdir), log_entry_mkdir, BTRFS_ACID_LOG_MKDIR);
	if (IS_ERR(log_entry)) {
		__log_destroy_mkdir(log_entry_mkdir);
		return PTR_ERR(log_entry);
	}
	BTRFS_SUB_DBG(LOG, "MKDIR: Adding to write-log\n");
	list_add(&log_entry->list, &snap->write_log);

	return 0;
}

int btrfs_acid_log_rmdir(struct inode * dir, struct dentry * dentry)
{
	struct btrfs_acid_snapshot * snap;
	struct btrfs_inode * dentry_inode;
	struct btrfs_acid_log_entry * log_entry;
	struct btrfs_acid_log_rmdir * log_entry_rmdir;

	if (!dir || !dentry || !dentry->d_inode)
		return -EINVAL;

	dentry_inode = BTRFS_I(dentry->d_inode);

	log_entry_rmdir =
			__log_create_rmdir(&dentry_inode->location, &dentry->d_name);
	if (IS_ERR(log_entry_rmdir))
		return PTR_ERR(log_entry_rmdir);

	snap = BTRFS_I(dir)->root->snap;
	log_entry = __log_create_entry(snap, &BTRFS_I(dir)->location,
			sizeof(*log_entry_rmdir), log_entry_rmdir, BTRFS_ACID_LOG_RMDIR);
	if (IS_ERR(log_entry)) {
		BTRFS_SUB_DBG(LOG, "#3\n");
		__log_destroy_rmdir(log_entry_rmdir);
		return PTR_ERR(log_entry);
	}
	BTRFS_SUB_DBG(LOG, "RMDIR: Adding to write-log\n");
	list_add(&log_entry->list, &snap->write_log);

	return 0;
}

int btrfs_acid_log_rename(struct inode * old_dir, struct dentry * old_dentry,
		struct inode * new_dir, struct dentry * new_dentry)
{
	struct btrfs_acid_snapshot * snap;
	struct btrfs_inode * old_d_inode, * new_d_inode;
	struct btrfs_acid_log_entry * log_entry;
	struct btrfs_acid_log_rename * log_rename;

	if (!old_dir || !old_dentry || !new_dir || !new_dentry)
		return -EINVAL;

	old_d_inode = BTRFS_I(old_dentry->d_inode);
	new_d_inode = BTRFS_I(new_dentry->d_inode);
	snap = BTRFS_I(old_dir)->root->snap;

	log_rename = __log_create_rename(&BTRFS_I(old_dir)->location,
			&old_dentry->d_name, &BTRFS_I(new_dir)->location,
			&new_dentry->d_name);
	if (IS_ERR(log_rename))
		return PTR_ERR(log_rename);

	log_entry = __log_create_entry(snap, &BTRFS_I(old_dir)->location,
			sizeof(*log_rename), log_rename, BTRFS_ACID_LOG_RENAME);
	if (IS_ERR(log_entry)) {
		__log_destroy_rename(log_rename);
		return PTR_ERR(log_entry);
	}
	BTRFS_SUB_DBG(LOG, "RENAME: Adding to write-log\n");
	list_add(&log_entry->list, &snap->write_log);

	return 0;
}

int btrfs_acid_log_symlink(struct inode * dir, struct dentry * dentry,
		const char * symname)
{
	struct btrfs_acid_log_entry * log_entry;
	struct btrfs_acid_log_symlink * log_symlink;

	if (!dir || !dentry || !dentry->d_inode || !symname)
		return -EINVAL;

	log_symlink = __log_create_symlink(&BTRFS_I(dir)->location,
			&dentry->d_name, &BTRFS_I(dentry->d_inode)->location, symname);
	if (IS_ERR(log_symlink))
		return PTR_ERR(log_symlink);

	log_entry = __log_create_entry(BTRFS_I(dir)->root->snap,
			&BTRFS_I(dir)->location, sizeof(*log_symlink), log_symlink,
			BTRFS_ACID_LOG_SYMLINK);
	if (IS_ERR(log_entry)) {
		__log_destroy_symlink(log_symlink);
		return PTR_ERR(log_entry);
	}
	BTRFS_SUB_DBG(LOG, "SYMLINK: Adding to write-log\n");
	list_add(&log_entry->list, &BTRFS_I(dir)->root->snap->write_log);

	return 0;
}

int btrfs_acid_log_setattr(struct dentry * dentry, struct iattr * attr)
{
	struct btrfs_acid_log_entry * log_entry;
	struct btrfs_acid_log_attr_rw * log_attr;
	struct btrfs_inode * inode;

	if (!dentry || !dentry->d_inode || !attr)
		return -EINVAL;

	log_attr = __log_create_attr_rw(dentry, attr->ia_valid);
	if (IS_ERR(log_attr))
		return PTR_ERR(log_attr);

	inode = BTRFS_I(dentry->d_inode);
	log_entry = __log_create_entry(inode->root->snap, &inode->location,
			sizeof(*log_attr), log_attr, BTRFS_ACID_LOG_ATTR_SET);
	if (IS_ERR(log_entry)) {
		__log_destroy_attr_rw(log_attr);
		return PTR_ERR(log_entry);
	}
	BTRFS_SUB_DBG(LOG, "SET-ATTR: Adding to write-log\n");
	list_add(&log_entry->list, &inode->root->snap->write_log);

	return 0;
}

int btrfs_acid_log_mknod(struct inode * dir, struct dentry * dentry,
		int mode, dev_t rdev)
{
	struct btrfs_acid_log_mknod * log_mknod;
	struct btrfs_acid_log_entry * log_entry;

	if (!dir || !dentry || !dentry->d_inode)
		return -EINVAL;

	log_mknod = __log_create_mknod(&BTRFS_I(dir)->location, &dentry->d_name,
			&BTRFS_I(dentry->d_inode)->location, mode, rdev);
	if (IS_ERR(log_mknod))
		return PTR_ERR(log_mknod);

	log_entry = __log_create_entry(BTRFS_I(dir)->root->snap,
			&BTRFS_I(dir)->location, sizeof(*log_mknod), log_mknod,
			BTRFS_ACID_LOG_MKNOD);
	if (IS_ERR(log_entry)) {
		__log_destroy_mknod(log_mknod);
		return PTR_ERR(log_entry);
	}
	BTRFS_SUB_DBG(LOG, "MKNOD: Adding to write-log\n");
	list_add(&log_entry->list, &BTRFS_I(dir)->root->snap->write_log);

	return 0;
}

int btrfs_acid_log_setxattr(struct dentry * dentry, const char * name,
		const void * value, size_t size, int flags)
{
	struct btrfs_acid_log_entry * log_entry;
	struct btrfs_acid_log_xattr * log_xattr;
	struct btrfs_inode * inode;

	if (!dentry || !dentry->d_inode || !name || !value)
		return -EINVAL;

	inode = BTRFS_I(dentry->d_inode);

	log_xattr = __log_create_xattr(&inode->location, &dentry->d_name,
			name, value, size, flags);
	if (IS_ERR(log_xattr))
		return PTR_ERR(log_xattr);

	log_entry = __log_create_entry(inode->root->snap, &inode->location,
			sizeof(*log_xattr), log_xattr, BTRFS_ACID_LOG_XATTR_SET);
	if (IS_ERR(log_entry)) {
		__log_destroy_xattr(log_xattr);
		return PTR_ERR(log_entry);
	}
	BTRFS_SUB_DBG(LOG, "SET-X-ATTR: Adding to write-log\n");
	list_add(&log_entry->list, &inode->root->snap->write_log);
	return 0;
}

int btrfs_acid_log_getxattr(struct dentry * dentry, const char * name)
{
	struct btrfs_acid_log_entry * log_entry;
	struct btrfs_acid_log_xattr * log_xattr;
	struct btrfs_inode * inode;

	if (!dentry || !dentry->d_inode || !name)
		return -EINVAL;

	inode = BTRFS_I(dentry->d_inode);

	log_xattr = __log_create_xattr(&inode->location, &dentry->d_name,
			name, NULL, 0, 0);
	if (IS_ERR(log_xattr))
		return PTR_ERR(log_xattr);

	log_entry = __log_create_entry(inode->root->snap, &inode->location,
			sizeof(*log_xattr), log_xattr, BTRFS_ACID_LOG_XATTR_GET);
	if (IS_ERR(log_entry)) {
		__log_destroy_xattr(log_xattr);
		return PTR_ERR(log_entry);
	}
	BTRFS_SUB_DBG(LOG, "GET-X-ATTR: Adding to read-log\n");
	list_add(&log_entry->list, &inode->root->snap->read_log);
	return 0;
}

int btrfs_acid_log_listxattr(struct dentry * dentry,
		char * buffer, size_t user_size, ssize_t real_size)
{
	struct btrfs_inode * inode;
	struct btrfs_acid_log_xattr * log_xattr;
	struct btrfs_acid_log_entry * log_entry;
	char * ptr, * attr_name;
	size_t missing;

	if (!dentry || !dentry->d_inode)
		return -EINVAL;

	inode = BTRFS_I(dentry->d_inode);
	missing = (user_size <= real_size ? user_size : real_size);
	ptr = buffer;
	while (1) {
		attr_name = ptr;
		for (; ptr && *(ptr++); );
		missing -= (ptr - attr_name);

		log_xattr = __log_create_xattr(&inode->location, &dentry->d_name,
				attr_name, NULL, 0, 0);
		if (IS_ERR(log_xattr))
			return PTR_ERR(log_xattr);

		log_entry = __log_create_entry(inode->root->snap, &inode->location,
				sizeof(*log_xattr), log_xattr, BTRFS_ACID_LOG_XATTR_LIST);
		if (IS_ERR(log_entry)) {
			__log_destroy_xattr(log_xattr);
			return PTR_ERR(log_entry);
		}

		BTRFS_SUB_DBG(LOG, "LIST-X-ATTR: Adding to read-log\n");
		list_add(&log_entry->list, &inode->root->snap->read_log);

		if (missing <= 0)
			break;
	}

	return 0;
}

int btrfs_acid_log_removexattr(struct dentry * dentry, const char * name)
{
	struct btrfs_acid_log_entry * log_entry;
	struct btrfs_acid_log_xattr * log_xattr;
	struct btrfs_inode * inode;

	if (!dentry || !dentry->d_inode || !name)
		return -EINVAL;

	inode = BTRFS_I(dentry->d_inode);
	log_xattr = __log_create_xattr(&inode->location, &dentry->d_name, name,
			NULL, 0, 0);
	if (IS_ERR(log_xattr))
		return PTR_ERR(log_xattr);
	log_entry = __log_create_entry(inode->root->snap, &inode->location,
			sizeof(*log_xattr), log_xattr, BTRFS_ACID_LOG_XATTR_REMOVE);
	if (IS_ERR(log_entry)) {
		__log_destroy_xattr(log_xattr);
		return PTR_ERR(log_entry);
	}
	BTRFS_SUB_DBG(LOG, "REMOVE-X-ATTR: Adding to write-log\n");
	list_add(&log_entry->list, &inode->root->snap->write_log);
	return 0;
}

int btrfs_acid_log_truncate(struct inode * inode)
{
	struct btrfs_acid_log_entry * log_entry;
	struct btrfs_acid_log_truncate * log_truncate;

	if (!inode)
		return -EINVAL;

	log_truncate =
			__log_create_truncate(&BTRFS_I(inode)->location, inode->i_size);
	if (IS_ERR(log_truncate))
		return PTR_ERR(log_truncate);
	log_entry = __log_create_entry(BTRFS_I(inode)->root->snap,
			&BTRFS_I(inode)->location, sizeof(*log_truncate), log_truncate,
			BTRFS_ACID_LOG_TRUNCATE);
	if (IS_ERR(log_entry)) {
		kfree(log_truncate);
		return PTR_ERR(log_entry);
	}
	BTRFS_SUB_DBG(LOG, "TRUNCATE: Adding to write-log\n");
	list_add(&log_entry->list, &BTRFS_I(inode)->root->snap->write_log);
	return 0;
}

int btrfs_acid_log_permission(struct inode * inode, int mask)
{
	struct btrfs_acid_log_entry * log_entry;
	struct btrfs_acid_log_permission * log_permission;

	if (!inode)
		return -EINVAL;

	log_permission = __log_create_permission(&BTRFS_I(inode)->location, mask);
	if (IS_ERR(log_permission))
		return PTR_ERR(log_permission);

	log_entry = __log_create_entry(BTRFS_I(inode)->root->snap,
			&BTRFS_I(inode)->location, sizeof(*log_permission), log_permission,
			BTRFS_ACID_LOG_PERMISSION);
	if (IS_ERR(log_entry)) {
		kfree(log_permission);
		return PTR_ERR(log_entry);
	}
	BTRFS_SUB_DBG(LOG, "PERMISSION: Adding to read-log\n");
	list_add(&log_entry->list, &BTRFS_I(inode)->root->snap->read_log);
	return 0;
}

int btrfs_acid_log_mmap(struct file * filp, struct vm_area_struct * vma)
{
	struct btrfs_acid_log_entry * log_entry;
	struct btrfs_acid_log_mmap * log_mmap;
	struct inode * inode;
	pgoff_t start, end;

	if (!filp || !vma)
		return -EINVAL;

	inode = fdentry(filp)->d_inode;

	start = vma->vm_pgoff;
	end = start + ((vma->vm_end - vma->vm_start - 1) >> PAGE_CACHE_SHIFT);

	log_mmap = __log_create_mmap(&BTRFS_I(inode)->location,
			&fdentry(filp)->d_name, start, end, vma->vm_page_prot,
			vma->vm_flags);
	if (IS_ERR(log_mmap))
		return PTR_ERR(log_mmap);

	log_entry = __log_create_entry(BTRFS_I(inode)->root->snap,
			&BTRFS_I(inode)->location, sizeof(*log_mmap), log_mmap,
			BTRFS_ACID_LOG_MMAP);
	if (IS_ERR(log_entry)) {
		__log_destroy_mmap(log_mmap);
		return PTR_ERR(log_entry);
	}
	BTRFS_SUB_DBG(LOG, "MMAP: Adding to read-log\n");
	list_add(&log_entry->list, &BTRFS_I(inode)->root->snap->read_log);

	return 0;
}

/**
 * btrfs_acid_log_page_mkwrite - Logs a write to a page (from mmap et al.)
 *
 * Uses the same struct and is logged with the same type as a common write. If
 * this causes any unforeseen problems, it will be changed.
 */
int btrfs_acid_log_page_mkwrite(struct vm_area_struct * vma,
		struct vm_fault * vmf)
{
	struct btrfs_acid_log_entry * log_entry;
	struct btrfs_acid_log_rw * rw_entry;
	struct inode * inode;

	if (!vma || !vmf)
		return -EINVAL;

	inode = fdentry(vma->vm_file)->d_inode;

	rw_entry = __log_create_rw(vmf->pgoff, vmf->pgoff);
	if (IS_ERR(rw_entry))
		return PTR_ERR(rw_entry);
	log_entry = __log_create_entry(BTRFS_I(inode)->root->snap,
			&BTRFS_I(inode)->location, sizeof(*rw_entry), rw_entry,
			BTRFS_ACID_LOG_WRITE);
	if (IS_ERR(log_entry)) {
		kfree(rw_entry);
		return PTR_ERR(log_entry);
	}
	BTRFS_SUB_DBG(LOG, "PAGE-MKWRITE: Adding to write-log\n");
	list_add(&log_entry->list, &BTRFS_I(inode)->root->snap->write_log);

	return 0;
}

static struct btrfs_acid_log_mmap *
__log_create_mmap(struct btrfs_key * location, struct qstr * name,
		pgoff_t start, pgoff_t end, pgprot_t prot, unsigned long flags)
{
	struct btrfs_acid_log_mmap * entry;
	int err;

	if (!location || !name)
		return ERR_PTR(-EINVAL);

	entry = kzalloc(sizeof(*entry), GFP_NOFS);
	if (!entry)
		return ERR_PTR(-EINVAL);

	__clone_keys(&entry->location, location);
	err = __clone_names(&entry->name, name);
	if (err < 0) {
		kfree(entry);
		return ERR_PTR(err);
	}

	entry->pages.first_page = start;
	entry->pages.last_page = end;
	entry->prot = prot;
	entry->flags = flags;

	return entry;
}

static void __log_destroy_mmap(struct btrfs_acid_log_mmap * entry)
{
	if (entry) {
		__free_name(&entry->name);
		kfree(entry);
	}
}

static struct btrfs_acid_log_permission *
__log_create_permission(struct btrfs_key * location, int mask)
{
	struct btrfs_acid_log_permission * entry;

	if (!location)
		return ERR_PTR(-EINVAL);

	entry = kzalloc(sizeof(*entry), GFP_NOFS);
	if (!entry)
		return ERR_PTR(-ENOMEM);
	__clone_keys(&entry->location, location);
	entry->mask = mask;

	return entry;
}


static struct btrfs_acid_log_truncate *
__log_create_truncate(struct btrfs_key * location, loff_t size)
{
	struct btrfs_acid_log_truncate * entry;

	if (!location)
		return ERR_PTR(-EINVAL);

	entry = kzalloc(sizeof(*entry), GFP_NOFS);
	if (!entry)
		return ERR_PTR(-ENOMEM);

	__clone_keys(&entry->location, location);
	entry->size = size;

	return entry;
}

/* 'attr_name' may be NULL if, and only if, we are logging a 'listxattr' that
 * does not return attributes (i.e., that returns only the number of extended
 * attributes). In that case, 'value' must also be NULL.
 */
static struct btrfs_acid_log_xattr *
__log_create_xattr(struct btrfs_key * location, struct qstr * name,
		const char * attr_name, const void * value, size_t size, int flags)
{
	int err;
	struct btrfs_acid_log_xattr * entry;
	struct qstr * qstr;

	if (!location || !name)
		return ERR_PTR(-EINVAL);

	if (!attr_name && value)
		return ERR_PTR(-EINVAL);

	entry = kzalloc(sizeof(*entry), GFP_NOFS);
	if (!entry)
		return ERR_PTR(-ENOMEM);

	__clone_keys(&entry->location, location);
	err = __clone_names(&entry->name, name);
	if (err < 0)
		goto err_free;

	if (!attr_name)
		goto out;

	qstr = &entry->attr_name;
	qstr->len = strlen(attr_name);
	qstr->name = kzalloc(sizeof(*qstr->name) * qstr->len, GFP_NOFS);
	if (!qstr->name)
		goto err_free_name;
	memcpy((void *) qstr->name, (void *) attr_name, qstr->len);

	/* we have zeroed 'entry' with kzalloc; we don't need to set 'value'
	 * and 'size' to zero if they are not set. */
	if (!value)
		goto out;

	entry->size = size;
	entry->value = kzalloc(sizeof(*entry->value) * size, GFP_NOFS);
	if (!entry->value)
		goto err_free_attr_name;
	memcpy(entry->value, value, size);

out:
	entry->flags = flags;

	return entry;

err_free_attr_name:
	__free_name(&entry->attr_name);
err_free_name:
	__free_name(&entry->name);
err_free:
	kfree(entry);
	return ERR_PTR(err);
}

static void __log_destroy_xattr(struct btrfs_acid_log_xattr * entry)
{
	if (entry) {
		__free_name(&entry->name);
		__free_name(&entry->attr_name);
		if (entry->value)
			kfree(entry->value);
		kfree(entry);
	}
}

static struct btrfs_acid_log_mknod *
__log_create_mknod(struct btrfs_key * parent_location, struct qstr * name,
		struct btrfs_key * location, int mode, dev_t rdev)
{
	int err;
	struct btrfs_acid_log_mknod * entry;

	if (!parent_location || !name || !location)
		return ERR_PTR(-EINVAL);

	entry = kzalloc(sizeof(*entry), GFP_NOFS);
	if (!entry)
		return ERR_PTR(-ENOMEM);

	__clone_keys(&entry->parent_location, parent_location);
	__clone_keys(&entry->location, location);
	err = __clone_names(&entry->name, name);
	if (err < 0) {
		kfree(entry);
		return ERR_PTR(err);
	}
	entry->mode = mode;
	entry->rdev = rdev;

	return entry;
}

static void __log_destroy_mknod(struct btrfs_acid_log_mknod * entry)
{
	if (entry) {
		__free_name(&entry->name);
		kfree(entry);
	}
}

static struct btrfs_acid_log_symlink *
__log_create_symlink(struct btrfs_key * parent_location, struct qstr * name,
		struct btrfs_key * location, const char * symname)
{
	int err;
	struct btrfs_acid_log_symlink * entry;
	struct qstr * qstr;

	if (!parent_location || !name || !location || !symname)
		return ERR_PTR(-EINVAL);

	entry = kzalloc(sizeof(*entry), GFP_NOFS);
	if (!entry)
		return ERR_PTR(-ENOMEM);

	__clone_keys(&entry->parent_location, parent_location);
	__clone_keys(&entry->location, location);
	err = __clone_names(&entry->name, name);
	if (err < 0)
		goto err_free;

	err = -ENOMEM;
	qstr = &entry->name;
	qstr->len = strlen(symname);
	qstr->name = kzalloc(sizeof(*qstr->name) * qstr->len, GFP_NOFS);
	if (!qstr->name)
		goto err_free_name;
	memcpy((void *) qstr->name, (void *) symname, qstr->len);
	qstr->hash = full_name_hash(qstr->name, qstr->len);

	return entry;

err_free_name:
	__free_name(&entry->name);
err_free:
	kfree(entry);
	return ERR_PTR(err);
}

static void __log_destroy_symlink(struct btrfs_acid_log_symlink * entry)
{
	if (entry) {
		__free_name(&entry->name);
		__free_name(&entry->symname);
		kfree(entry);
	}
}

static struct btrfs_acid_log_rename *
__log_create_rename(struct btrfs_key * old_key, struct qstr * old_name,
		struct btrfs_key * new_key, struct qstr * new_name)
{
	int err;
	struct btrfs_acid_log_rename * entry;

	if (!old_key || !old_name || !new_key || !new_name)
		return ERR_PTR(-EINVAL);

	err = -ENOMEM;
	entry = kzalloc(sizeof(*entry), GFP_NOFS);
	if (!entry)
		goto err;

	__clone_keys(&entry->old_location, old_key);
	__clone_keys(&entry->new_location, new_key);

	err = __clone_names(&entry->old_name, old_name);
	if (err < 0)
		goto err_old_name;
	err = __clone_names(&entry->new_name, new_name);
	if (err < 0)
		goto err_new_name;
	return entry;

err_new_name:
	__free_name(&entry->old_name);
err_old_name:
	kfree(entry);
err:
	return ERR_PTR(err);
}

static void __log_destroy_rename(struct btrfs_acid_log_rename * entry)
{
	if (entry) {
		__free_name(&entry->old_name);
		__free_name(&entry->new_name);
	}
}

static struct btrfs_acid_log_rmdir *
__log_create_rmdir(struct btrfs_key * key, struct qstr * name)
{
	int err;
	struct btrfs_acid_log_rmdir * entry;

	if (!key || !name)
		return ERR_PTR(-EINVAL);

	entry = kzalloc(sizeof(*entry), GFP_NOFS);
	if (!entry)
		return ERR_PTR(-ENOMEM);

	__clone_keys(&entry->location, key);
	err = __clone_names(&entry->name, name);
	if (err < 0) {
		kfree(entry);
		return ERR_PTR(err);
	}
	return entry;
}

static void __log_destroy_rmdir(struct btrfs_acid_log_rmdir * entry)
{
	if (entry) {
		__free_name(&entry->name);
		kfree(entry);
	}
}

static struct btrfs_acid_log_mkdir *
__log_create_mkdir(struct btrfs_key * key, struct qstr * name, int mode)
{
	int err;
	struct btrfs_acid_log_mkdir * entry;

	entry = kzalloc(sizeof(*entry), GFP_NOFS);
	if (!entry)
		return ERR_PTR(-ENOMEM);

	__clone_keys(&entry->location, key);
	err = __clone_names(&entry->name, name);
	if (err < 0) {
		kfree(entry);
		return ERR_PTR(err);
	}
	entry->mode = mode;

	return entry;
}

static void
__log_destroy_mkdir(struct btrfs_acid_log_mkdir * entry)
{
	if (!entry)
		return;
	__free_name(&entry->name);
	kfree(entry);
}

static struct btrfs_acid_log_link *
__log_create_link(struct btrfs_key * old_key, struct qstr * old_name,
		struct btrfs_key * new_key, struct qstr * new_name)
{
	int err;
	struct btrfs_acid_log_link * entry;

	if (!old_key || !old_name || !new_key || !new_name)
		return ERR_PTR(-EINVAL);

	entry = kzalloc(sizeof(*entry), GFP_NOFS);
	if (!entry)
		return ERR_PTR(-ENOMEM);

	__clone_keys(&entry->old_location, old_key);
	__clone_keys(&entry->new_location, new_key);

	err = __clone_names(&entry->old_name, old_name);
	if (err < 0)
		return ERR_PTR(err);
	err = __clone_names(&entry->new_name, new_name);
	if (err < 0) {
		__free_name(&entry->new_name);
		return ERR_PTR(err);
	}

	return entry;
}

static void __log_destroy_link(struct btrfs_acid_log_link * entry)
{
	if (!entry)
		return;

	__free_name(&entry->old_name);
	__free_name(&entry->new_name);
	kfree(entry);
}

static struct btrfs_acid_log_unlink *
__log_create_unlink(struct btrfs_key * inode_key, struct qstr * d_name)
{
	struct btrfs_acid_log_unlink * log_entry_unlink;
	struct qstr * qstr;

	log_entry_unlink = kzalloc(sizeof(*log_entry_unlink), GFP_NOFS);
	if (!log_entry_unlink)
		return ERR_PTR(-ENOMEM);

	log_entry_unlink->location.objectid = inode_key->objectid;
	log_entry_unlink->location.type = inode_key->type;
	log_entry_unlink->location.offset = inode_key->offset;

	qstr = &log_entry_unlink->name;
	qstr->hash = d_name->hash;
	qstr->len = d_name->len;
	qstr->name = kzalloc(sizeof(*qstr->name) * qstr->len, GFP_NOFS);
	if (!qstr->name) {
		kfree(log_entry_unlink);
		return ERR_PTR(-ENOMEM);
	}
	memcpy((void *) qstr->name, d_name->name, qstr->len);

	return log_entry_unlink;
}

static void
__log_destroy_unlink(struct btrfs_acid_log_unlink * entry)
{
	if (!entry)
		return;

	if (entry->name.name)
		kfree(entry->name.name);
	kfree(entry);
}

/* Yes, this method name is h-o-r-r-i-b-l-e. But it creates a 'create' log
 * entry. I.e., when a 'creat()' is issued and we need to log it, we must
 * create a 'create' log entry, to guarantee the 'create' is logged. I could
 * go on... */
static struct btrfs_acid_log_create *
__log_create_create(struct btrfs_key * inode_key,
		struct qstr * d_name, int mode)
{
	struct btrfs_acid_log_create * log_entry_create;
	struct qstr * ptr;

	if (!inode_key || !d_name)
		return ERR_PTR(-EINVAL);

	log_entry_create = kzalloc(sizeof(*log_entry_create), GFP_NOFS);
	if (!log_entry_create)
		return ERR_PTR(-ENOMEM);

	log_entry_create->location.objectid = inode_key->objectid;
	log_entry_create->location.type = inode_key->type;
	log_entry_create->location.offset = inode_key->offset;

	ptr = &log_entry_create->name;
	ptr->hash = d_name->hash;
	ptr->len = d_name->len;
	ptr->name = kzalloc(sizeof(*ptr->name) * ptr->len, GFP_NOFS);
	if (!ptr->name) {
		kfree(log_entry_create);
		return ERR_PTR(-ENOMEM);
	}
	memcpy((void *) ptr->name, d_name->name, ptr->len);
	log_entry_create->mode = mode;

	return log_entry_create;
}

static void
__log_destroy_create(struct btrfs_acid_log_create * entry)
{
	if (!entry)
		return;

	if (entry->name.name)
		kfree(entry->name.name);
	kfree(entry);
}

static struct btrfs_acid_log_attr_rw *
__log_create_attr_rw(struct dentry * dentry, unsigned int flags)
{
	struct btrfs_acid_log_attr_rw * entry;
	struct btrfs_inode * inode;
	int err;

	if (!dentry || !dentry->d_inode)
		return ERR_PTR(-EINVAL);

	entry = kzalloc(sizeof(*entry), GFP_NOFS);
	if (!entry)
		return ERR_PTR(-ENOMEM);

	inode = BTRFS_I(dentry->d_inode);
	__clone_keys(&entry->location, &inode->location);
	err = __clone_names(&entry->name, &dentry->d_name);
	if (err < 0) {
		kfree(entry);
		return ERR_PTR(err);
	}
	entry->flags = flags;

	return entry;
}

static void __log_destroy_attr_rw(struct btrfs_acid_log_attr_rw * entry)
{
	if (entry) {
		__free_name(&entry->name);
		kfree(entry);
	}
}

/*
 * Create a 'Read/Write' entry for the log. Both reads and writes share the
 * same attributes when it comes to logging, so we use the same struct for
 * both of them.
 */
static struct btrfs_acid_log_rw *
__log_create_rw(pgoff_t first, pgoff_t last)
{
	struct btrfs_acid_log_rw * entry;

	if (last < first)
		return ERR_PTR(-EINVAL);

	entry = kzalloc(sizeof(*entry), GFP_NOFS);
	if (!entry)
		return ERR_PTR(-ENOMEM);

	entry->first_page = first;
	entry->last_page = last;

	return entry;
}

static struct btrfs_acid_log_entry *
__log_create_entry(struct btrfs_acid_snapshot * snap,
		struct btrfs_key * location,
		size_t size, void * data, u32 type)
{
	struct btrfs_acid_ctl * ctl;
	struct btrfs_acid_log_entry * entry;
	int clock;

	/* we may have a NULL data entry, as long as size is 0 (zero) */
	if (!snap || !location || (!data && size) || (data && !size))
		return ERR_PTR(-EINVAL);

	entry = kzalloc(sizeof(*entry), GFP_NOFS);
	if (!entry)
		return ERR_PTR(-ENOMEM);

	ctl = &snap->root->fs_info->acid_ctl;
	clock = atomic_inc_return(&ctl->clock);

	entry->clock = clock;
	entry->size = size;
	entry->data = data;
	entry->type = type;

	entry->location.objectid = location->objectid;
	entry->location.type = location->type;
	entry->location.offset = location->offset;

	return entry;
}

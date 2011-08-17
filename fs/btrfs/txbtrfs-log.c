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
__log_create_mmap(struct btrfs_inode * parent, struct btrfs_inode * inode,
		struct qstr * name,
		pgoff_t start, pgoff_t end, pgprot_t prot, unsigned long flags);
static struct btrfs_acid_log_permission *
__log_create_permission(struct btrfs_key * location, int mask);
static struct btrfs_acid_log_truncate *
__log_create_truncate(struct btrfs_key * location, loff_t size);
static struct btrfs_acid_log_xattr *
__log_create_xattr(struct btrfs_inode * parent, struct btrfs_inode * inode,
		struct qstr * name,
		const char * attr_name, const void * value, size_t size, int flags);
static struct btrfs_acid_log_mknod *
__log_create_mknod(struct btrfs_inode * parent, struct btrfs_inode * inode,
		struct qstr * name, int mode, dev_t rdev);
static struct btrfs_acid_log_symlink *
__log_create_symlink(struct btrfs_inode * parent, struct btrfs_inode * inode,
		struct qstr * name, const char * symname);
static struct btrfs_acid_log_rename *
__log_create_rename(struct btrfs_inode * old_parent,
		struct btrfs_inode * old_inode, struct qstr * old_name,
		struct btrfs_inode * new_parent, struct btrfs_inode * new_inode,
		struct qstr * new_name);
static struct btrfs_acid_log_readdir *
__log_create_readdir(struct btrfs_inode * inode, struct qstr * name);
static struct btrfs_acid_log_rmdir *
__log_create_rmdir(struct btrfs_inode * parent, struct btrfs_inode * inode,
		struct qstr * name);
static struct btrfs_acid_log_mkdir *
__log_create_mkdir(struct btrfs_inode * parent, struct btrfs_inode * inode,
		struct qstr * name, int mode);
static struct btrfs_acid_log_link *
__log_create_link(struct btrfs_inode * old_parent,
		struct btrfs_inode * old_inode, struct qstr * old_name,
		struct btrfs_inode * new_parent, struct btrfs_inode * new_inode,
		struct qstr * new_name, unsigned int inode_nlink);
static struct btrfs_acid_log_unlink *
__log_create_unlink(struct btrfs_inode * parent, struct btrfs_inode * inode,
		struct qstr * name, unsigned int nlink);
static struct btrfs_acid_log_create *
__log_create_create(struct btrfs_inode * parent, struct btrfs_inode * inode,
		struct qstr * name, int mode);
static struct btrfs_acid_log_attr *
__log_create_attr(struct btrfs_inode * parent, struct btrfs_inode * inode,
		struct qstr * name, unsigned int flags);
static struct btrfs_acid_log_rw *
__log_create_rw(struct btrfs_inode * parent, struct btrfs_inode * inode,
		struct qstr * name,
		pgoff_t first, pgoff_t last, unsigned int nlink);
static struct btrfs_acid_log_entry *
__log_create_entry(struct btrfs_acid_snapshot * snap,
		struct btrfs_key * location,
		size_t size, void * data, u32 type);
static int
__log_create_file(struct btrfs_acid_log_file * file,
		struct btrfs_key * parent, struct btrfs_key * location,
		struct qstr * name);

/* destruction methods */
static void
__log_destroy_create(struct btrfs_acid_log_create * entry);
static void
__log_destroy_unlink(struct btrfs_acid_log_unlink * entry);
static void __log_destroy_link(struct btrfs_acid_log_link * entry);
static void
__log_destroy_mkdir(struct btrfs_acid_log_mkdir * entry);
static void __log_destroy_readdir(struct btrfs_acid_log_readdir * entry);
static void __log_destroy_rmdir(struct btrfs_acid_log_rmdir * entry);
static void __log_destroy_rename(struct btrfs_acid_log_rename * entry);
static void __log_destroy_symlink(struct btrfs_acid_log_symlink * entry);
static void __log_destroy_attr(struct btrfs_acid_log_attr * entry);
static void __log_destroy_mknod(struct btrfs_acid_log_mknod * entry);
static void __log_destroy_truncate(struct btrfs_acid_log_truncate * entry);
static void __log_destroy_permission(struct btrfs_acid_log_permission * entry);
static void __log_destroy_xattr(struct btrfs_acid_log_xattr * entry);
static void __log_destroy_mmap(struct btrfs_acid_log_mmap * entry);
static void __log_destroy_rw(struct btrfs_acid_log_rw * entry);
static void __log_destroy_entry(struct btrfs_acid_log_entry * entry);

static void
__log_destroy_file(struct btrfs_acid_log_file * file);

static int btrfs_acid_log_cr_insert(struct btrfs_acid_snapshot * snap,
		struct btrfs_acid_log_entry * log_entry, u64 parent, u64 ino);

static char * type_to_str[] = {
		"READ",			/* 1 */
		"WRITE",		/* 2 */
		"ATTR_GET",		/* 3 */
		"ATTR_SET",		/* 4 */
		"READDIR",		/* 5 */
		"CREATE",		/* 6 */
		"UNLINK",		/* 7 */
		"LINK",			/* 8 */
		"MKDIR",		/* 9 */
		"RMDIR",		/* 10 */
		"RENAME",		/* 11 */
		"SYMLINK",		/* 12 */
		"MKNOD", 		/* 13 */
		"XATTR_SET",	/* 14 */
		"XATTR_GET", 	/* 15 */
		"XATTR_LIST",	/* 16 */
		"XATTR_REMOVE",	/* 17 */
		"TRUNCATE",		/* 18 */
		"PERMISSION",	/* 19 */
		"MMAP",			/* 20 */
};

static char * __log_type_to_str(u16 type)
{
	return type_to_str[type-1];
}

static int
__log_op_add(struct btrfs_acid_snapshot * snap, void * entry, u64 ino, u16 type)
{
	struct btrfs_acid_log_entry * log_entry;

	if (!snap || !entry || !type)
		return -EINVAL;

	mutex_lock(&snap->op_log_mutex);

	log_entry = (struct btrfs_acid_log_entry *) entry;
	log_entry->clock = atomic_inc_return(&snap->clock);
	log_entry->type = type;
	log_entry->ino = ino;

	list_add_tail(&log_entry->list, &snap->op_log);

	mutex_unlock(&snap->op_log_mutex);
	return 0;
}

/*
 * Adds a 'read' entry to the read-set.
 */
//int btrfs_acid_log_read(struct btrfs_acid_snapshot * snap,
//		struct btrfs_key * location, pgoff_t first, pgoff_t last)
int btrfs_acid_log_read(struct btrfs_inode * parent, struct btrfs_inode * inode,
		struct qstr * name, pgoff_t first, pgoff_t last)
{
	int ret = 0;
	struct btrfs_acid_log_rw * rw_entry;
	unsigned int nlink;
//	struct btrfs_acid_log_entry * log_entry;

	if (!parent || !inode || !name)
		return -EINVAL;

	nlink = inode->vfs_inode.i_nlink;

	rw_entry = __log_create_rw(parent, inode, name, first, last, nlink);
	if (IS_ERR(rw_entry))
		return PTR_ERR(rw_entry);

	ret = __log_op_add(inode->root->snap, rw_entry, inode->location.objectid,
			BTRFS_ACID_LOG_READ);
	if (ret < 0) {
		__log_destroy_rw(rw_entry);
		return ret;
	}
	return 0;

	#if 0
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

	BTRFS_SUB_DBG(LOG, "READ: Adding to read-log\n");
	list_add(&log_entry->list, &snap->read_log);
	return ret;

err_destroy_rw_entry:
	kfree(rw_entry);
	return ret;
#endif
}

/*
 * Adds a 'write' entry to the write-set.
 */
//int btrfs_acid_log_write(struct btrfs_acid_snapshot * snap,
//		struct btrfs_key * location, pgoff_t first, pgoff_t last)
int btrfs_acid_log_write(struct btrfs_inode * parent,
		struct btrfs_inode * inode, struct qstr * name,
		pgoff_t first, pgoff_t last)
{
	int ret = 0;
	struct btrfs_acid_log_rw * rw_entry;
	unsigned int nlink;
//	struct btrfs_acid_log_entry * log_entry;

	/*BTRFS_SUB_DBG(LOG, "WRITE: inode [%llu %d %llu] "
				"first page = %d, last page = %d\n",
				location->objectid, location->type, location->offset,
				first, last);*/
	if (!parent || !inode || !name)
		return -EINVAL;

	nlink = inode->vfs_inode.i_nlink;

	rw_entry = __log_create_rw(parent, inode, name, first, last, nlink);
	if (IS_ERR(rw_entry))
		return PTR_ERR(rw_entry);

	ret = __log_op_add(inode->root->snap, rw_entry, inode->location.objectid,
			BTRFS_ACID_LOG_WRITE);
	if (ret < 0) {
		__log_destroy_rw(rw_entry);
		return ret;
	}
	return 0;
#if 0
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
#endif
}

/* Adds an entry to the log referring to a 'get attrs' issued on an inode. */
//int btrfs_acid_log_getattr(struct inode * inode)
int btrfs_acid_log_getattr(struct dentry * dentry)
{
	struct btrfs_acid_snapshot * snap;
	struct btrfs_inode * parent, * inode;
	struct btrfs_acid_log_attr * attr_rw_entry;
//	struct btrfs_acid_log_entry * log_entry;
	int err;

	if (unlikely(!dentry || !dentry->d_inode))
		return -EINVAL;

//	our_inode = BTRFS_I(inode);
	parent = BTRFS_I(dentry->d_parent->d_inode);
	inode = BTRFS_I(dentry->d_inode);
	snap = inode->root->snap;

	if (!snap)
		return -ENOTSUPP;

//	attr_rw_entry = __log_create_attr_rw(0);
//	attr_rw_entry = __log_create_attr(dentry, 0);
	attr_rw_entry = __log_create_attr(parent, inode, &dentry->d_name, 0);
	if (IS_ERR(attr_rw_entry))
		return PTR_ERR(attr_rw_entry);

	err = __log_op_add(snap, attr_rw_entry, inode->location.objectid,
			BTRFS_ACID_LOG_ATTR_GET);
	if (err < 0) {
		__log_destroy_attr(attr_rw_entry);
		return err;
	}
#if 0
	log_entry = __log_create_entry(snap, &inode->location,
			sizeof(*attr_rw_entry), attr_rw_entry, BTRFS_ACID_LOG_ATTR_GET);
	if (IS_ERR(log_entry)) {
		kfree(attr_rw_entry);
		return PTR_ERR(log_entry);
	}

	BTRFS_SUB_DBG(LOG, "GET-ATTR: Adding to read-log\n");
	list_add(&log_entry->list, &snap->read_log);
#endif
	return 0;
}

int btrfs_acid_log_readdir(struct file * filp)
{
	struct btrfs_acid_log_readdir * log_entry;
	struct btrfs_acid_snapshot * snap;
	struct btrfs_inode * inode;
	struct qstr * name;
	struct dentry * file_dentry;
	int err;

	if (!filp)
		return -EINVAL;

	file_dentry = fdentry(filp);
	inode = BTRFS_I(file_dentry->d_inode);
	name = &file_dentry->d_name;
	snap = inode->root->snap;

	if (!snap)
		return -ENOTSUPP;

	log_entry = __log_create_readdir(inode, name);
	if (IS_ERR(log_entry))
		return PTR_ERR(log_entry);

	err = __log_op_add(snap, log_entry, inode->location.objectid,
			BTRFS_ACID_LOG_READDIR);
	if (err < 0) {
		__log_destroy_readdir(log_entry);
		return err;
	}

	return 0;
}

#if 0
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
#endif

/* Adds an entry to the log referring to a 'creat()'. */
int btrfs_acid_log_create(struct inode * dir, struct dentry * dentry, int mode)
{
#if 0
	struct btrfs_acid_log_entry * log_entry;
	struct btrfs_acid_log_create * log_entry_create;
#endif
	struct btrfs_acid_log_create * log_entry;
	struct btrfs_acid_snapshot * snap;
	struct btrfs_root * root;
	struct btrfs_inode * inode, * parent_inode;
	struct qstr * d_name;
	int ret = 0;

	if (!dir || !dentry || !dentry->d_inode)
		return -EINVAL;

	parent_inode = BTRFS_I(dir);
	inode = BTRFS_I(dentry->d_inode);
	root = parent_inode->root;
	snap = root->snap;
	d_name = &dentry->d_name;

#if 0
	log_entry_create = __log_create_create(mode);
	if (IS_ERR(log_entry_create))
		return PTR_ERR(log_entry_create);

	ret = __log_create_location(&log_entry_create->location,
			&our_parent_inode->location, &our_inode->location, d_name);
	if (ret < 0) {
		__log_destroy_create(log_entry_create);
		return ret;
	}

	log_entry = __log_create_entry(snap, &our_inode->location,
			sizeof(*log_entry_create), log_entry_create, BTRFS_ACID_LOG_CREATE);
	if (IS_ERR(log_entry)) {
		__log_destroy_create(log_entry_create);
		return PTR_ERR(log_entry);
	}

	BTRFS_SUB_DBG(LOG, "CREATE: Adding to write-log\n");
	list_add(&log_entry->list, &snap->write_log);

	ret = btrfs_acid_log_cr_insert(snap, log_entry,
			dir->i_ino, dentry->d_inode->i_ino);
	if (ret < 0) {
		BTRFS_SUB_DBG(LOG, "CREATE: Error logging to CRL\n");
	}
#else
	log_entry = __log_create_create(parent_inode, inode, d_name, mode);
	if (IS_ERR(log_entry)) {
		return PTR_ERR(log_entry);
	}

	ret = __log_op_add(snap, log_entry, inode->location.objectid,
			BTRFS_ACID_LOG_CREATE);
	if (ret < 0)
		__log_destroy_create(log_entry);

#endif

	return ret;
}

int btrfs_acid_log_unlink(struct inode * dir, struct dentry * dentry)
{
//	struct btrfs_acid_log_entry * log_entry;
	struct btrfs_acid_log_unlink * log_entry;
	struct btrfs_acid_snapshot * snap;
	struct btrfs_inode * inode, * parent_inode;
	struct qstr * d_name;
	int ret = 0;

	if (!dir || !dentry || !dentry->d_inode)
		return -EINVAL;

	parent_inode = BTRFS_I(dir);
	inode = BTRFS_I(dentry->d_inode);
	snap = parent_inode->root->snap;
	d_name = &dentry->d_name;

	log_entry = __log_create_unlink(parent_inode, inode, d_name,
			dentry->d_inode->i_nlink);
	if (IS_ERR(log_entry))
		return PTR_ERR(log_entry);

	ret = __log_op_add(snap, log_entry, inode->location.objectid,
			BTRFS_ACID_LOG_UNLINK);
	if (ret < 0) {
		__log_destroy_unlink(log_entry);
	}

#if 0
	ret = __log_create_file(&log_entry_unlink->location,
			&parent_inode->location, &our_inode->location, d_name);
	if (ret < 0) {
		__log_destroy_unlink(log_entry_unlink);
		return ret;
	}

	log_entry = __log_create_entry(snap, &our_inode->location,
			sizeof(*log_entry_unlink), log_entry_unlink, BTRFS_ACID_LOG_UNLINK);
	if (IS_ERR(log_entry)) {
		__log_destroy_unlink(log_entry_unlink);
		return PTR_ERR(log_entry);
	}

	log_entry->nlink = dentry->d_inode->i_nlink;

	BTRFS_SUB_DBG(LOG, "UNLINK: Adding to write-log\n");
	list_add(&log_entry->list, &snap->write_log);

	ret = btrfs_acid_log_cr_insert(snap, log_entry,
			dir->i_ino, dentry->d_inode->i_ino);
	if (ret < 0) {
		BTRFS_SUB_DBG(LOG, "UNLINK: Error logging to CRL\n");
	}
#else

#endif

	return 0;
}

int btrfs_acid_log_link(struct dentry * old_dentry, struct inode * dir,
		struct dentry * new_dentry)
{
//	struct btrfs_acid_log_entry * log_entry;
	struct btrfs_acid_log_link * log_entry;
	struct btrfs_acid_snapshot * snap;
	struct btrfs_inode * new_inode, * new_parent_inode;
	struct btrfs_inode * old_inode, * old_parent_inode;
	struct qstr * new_name, * old_name;
//	struct dentry * old_parent_dentry, * new_parent_dentry;
	int ret = 0;

	if (!old_dentry || !dir || !new_dentry) {
		BTRFS_SUB_DBG(LOG, "ERROR: LINK: NULL params\n");
		return -EINVAL;
	}

#if 0
	old_parent_dentry = dget_parent(old_dentry);
	new_parent_dentry = dget_parent(new_dentry);
	old_inode = BTRFS_I(old_dentry->d_inode);
	new_inode = BTRFS_I(new_dentry->d_inode);
#endif

	old_parent_inode = BTRFS_I(old_dentry->d_parent->d_inode);
	old_inode = BTRFS_I(old_dentry->d_inode);
	old_name = &old_dentry->d_name;
	new_parent_inode = BTRFS_I(new_dentry->d_parent->d_inode);
	new_inode = BTRFS_I(new_dentry->d_inode);
	new_name = &new_dentry->d_name;

	snap = old_inode->root->snap;

	log_entry = __log_create_link(old_parent_inode, old_inode, old_name,
			new_parent_inode, new_inode, new_name, new_dentry->d_inode->i_nlink);
	if (IS_ERR(log_entry)) {
		return PTR_ERR(log_entry);
	}

	ret = __log_op_add(snap, log_entry, old_inode->location.objectid,
			BTRFS_ACID_LOG_LINK);
	if (ret < 0) {
		__log_destroy_link(log_entry);
		return ret;
	}


#if 0
	log_entry = __log_create_link();
	if (IS_ERR(log_entry))
		return PTR_ERR(log_entry);

	ret = __log_create_file(&log_entry->old_location,
			&BTRFS_I(old_parent_dentry->d_inode)->location,
			&old_inode->location, &old_dentry->d_name);
	if (ret < 0) {
		__log_destroy_link(log_entry);
		return ret;
	}

	ret = __log_create_file(&log_entry->new_location,
			&BTRFS_I(new_parent_dentry->d_inode)->location,
			&new_inode->location, &new_dentry->d_name);
	if (ret < 0) {
		__log_destroy_link(log_entry);
		return ret;
	}

	log_entry = __log_create_entry(snap, &new_inode->location,
			sizeof(*log_entry), log_entry, BTRFS_ACID_LOG_LINK);
	if (IS_ERR(log_entry)) {
		__log_destroy_link(log_entry);
		return PTR_ERR(log_entry);
	}

	BTRFS_SUB_DBG(LOG, "LINK: Adding to write-log\n");
	list_add(&log_entry->list, &snap->write_log);

	/* Although having two parents available (one for the target inode and
	 * another for the link's final inode), we will log it only on the parent
	 * to which the link's will belong to -- there is no change in the other
	 * parent whatsoever.
	 */
	ret = btrfs_acid_log_cr_insert(snap, log_entry,
			dir->i_ino, new_dentry->d_inode->i_ino);
	if (ret < 0) {
		BTRFS_SUB_DBG(LOG, "LINK: Error logging to CRL (parent = %llu)\n",
				dir->i_ino);
	}
#endif

	return ret;
}

int btrfs_acid_log_mkdir(struct inode * dir, struct dentry * dentry, int mode)
{
	struct btrfs_acid_snapshot * snap;
	struct btrfs_inode * dir_inode, * dentry_inode;
	struct qstr * qstr;
//	struct btrfs_acid_log_entry * log_entry;
	struct btrfs_acid_log_mkdir * log_entry;
	int ret = 0;

	if (!dir || !dentry || !dentry->d_inode)
		return -EINVAL;

	dir_inode = BTRFS_I(dir);
	dentry_inode = BTRFS_I(dentry->d_inode);
	qstr = &dentry->d_name;
	snap = dir_inode->root->snap;

	log_entry = __log_create_mkdir(dir_inode, dentry_inode, qstr, mode);
	if (IS_ERR(log_entry))
		return PTR_ERR(log_entry);

	ret = __log_op_add(snap, log_entry, dentry_inode->location.objectid,
			BTRFS_ACID_LOG_MKDIR);
	if (ret < 0)
		return ret;

#if 0
	log_entry =
			__log_create_mkdir(mode);
	if (IS_ERR(log_entry))
		return PTR_ERR(log_entry);
	ret = __log_create_file(&log_entry->location,
			&dir_inode->location, &dentry_inode->location, qstr);
	if (ret < 0) {
		__log_destroy_mkdir(log_entry);
		return ret;
	}

	log_entry = __log_create_entry(snap, &dentry_inode->location,
			sizeof(*log_entry), log_entry, BTRFS_ACID_LOG_MKDIR);
	if (IS_ERR(log_entry)) {
		__log_destroy_mkdir(log_entry);
		return PTR_ERR(log_entry);
	}
	BTRFS_SUB_DBG(LOG, "MKDIR: Adding to write-log\n");
	list_add(&log_entry->list, &snap->write_log);

	ret = btrfs_acid_log_cr_insert(snap, log_entry,
			dir->i_ino, dentry->d_inode->i_ino);
	if (ret < 0) {
		BTRFS_SUB_DBG(LOG, "MKDIR: Error logging to CRL\n");
	}
#endif

	return ret;
}

int btrfs_acid_log_rmdir(struct inode * dir, struct dentry * dentry)
{
	struct btrfs_acid_snapshot * snap;
	struct btrfs_inode * dentry_inode;
//	struct btrfs_acid_log_entry * log_entry;
	struct btrfs_acid_log_rmdir * log_entry;
	int ret = 0;

	if (!dir || !dentry || !dentry->d_inode)
		return -EINVAL;

	dentry_inode = BTRFS_I(dentry->d_inode);
	snap = dentry_inode->root->snap;

	log_entry = __log_create_rmdir(BTRFS_I(dir), dentry_inode, &dentry->d_name);
	if (IS_ERR(log_entry))
		return PTR_ERR(log_entry);

	ret = __log_op_add(snap, log_entry, dentry_inode->location.objectid,
			BTRFS_ACID_LOG_RMDIR);
	if (ret < 0) {
		__log_destroy_rmdir(log_entry);
		return ret;
	}

#if 0
	log_entry_rmdir =
			__log_create_rmdir();
	if (IS_ERR(log_entry_rmdir))
		return PTR_ERR(log_entry_rmdir);

	ret = __log_create_file(&log_entry_rmdir->location,
			&BTRFS_I(dir)->location, &dentry_inode->location, &dentry->d_name);
	if (ret < 0) {
		__log_destroy_rmdir(log_entry_rmdir);
		return ret;
	}

	snap = BTRFS_I(dir)->root->snap;
	log_entry = __log_create_entry(snap, &dentry_inode->location,
			sizeof(*log_entry_rmdir), log_entry_rmdir, BTRFS_ACID_LOG_RMDIR);
	if (IS_ERR(log_entry)) {
		BTRFS_SUB_DBG(LOG, "#3\n");
		__log_destroy_rmdir(log_entry_rmdir);
		return PTR_ERR(log_entry);
	}
	BTRFS_SUB_DBG(LOG, "RMDIR: Adding to write-log\n");
	list_add(&log_entry->list, &snap->write_log);

	ret = btrfs_acid_log_cr_insert(snap, log_entry,
			dir->i_ino, dentry->d_inode->i_ino);
	if (ret < 0) {
		BTRFS_SUB_DBG(LOG, "RMDIR: Error logging to CRL\n");
	}
#endif

	return 0;
}

/**
 * btrfs_acid_log_rename -- logs a rename call under tx context.
 *
 * @new_dentry: the new file's name.
 *
 * @new_dentry d_inode field may be NULL if the file we're renaming to does not
 * exist.
 */
int btrfs_acid_log_rename(struct inode * old_dir, struct dentry * old_dentry,
		struct inode * new_dir, struct dentry * new_dentry)
{
	struct btrfs_acid_snapshot * snap;
	struct btrfs_inode * old_parent, * old_d_inode;
	struct btrfs_inode * new_parent, * new_d_inode = NULL;
	struct qstr * old_d_name, * new_d_name;
//	struct btrfs_acid_log_entry * log_entry;
	struct btrfs_acid_log_rename * log_rename;
	int dst_exists = 1; // at first, assume destination inode exists.
	int ret = 0;

	if (!old_dir || !old_dentry || !new_dir || !new_dentry)
		return -EINVAL;

	if (!new_dentry->d_inode)
		dst_exists = 0;

	old_parent = BTRFS_I(old_dir);
	old_d_inode = BTRFS_I(old_dentry->d_inode);
	old_d_name = &old_dentry->d_name;

	new_parent = BTRFS_I(new_dir);
	if (dst_exists)
		new_d_inode = BTRFS_I(new_dentry->d_inode);
	new_d_name = &new_dentry->d_name;

	snap = BTRFS_I(old_dir)->root->snap;

	log_rename = __log_create_rename(old_parent, old_d_inode, old_d_name,
			new_parent, new_d_inode, new_d_name);
	if (IS_ERR(log_rename))
		return PTR_ERR(log_rename);

	ret = __log_op_add(snap, log_rename, old_d_inode->location.objectid,
			BTRFS_ACID_LOG_RENAME);
	if (ret < 0) {
		__log_destroy_rename(log_rename);
		return ret;
	}

#if 0
	log_rename = __log_create_rename();
	if (IS_ERR(log_rename))
		return PTR_ERR(log_rename);

	ret = __log_create_file(&log_rename->old_location,
			&BTRFS_I(old_dir)->location, &old_d_inode->location,
			&old_dentry->d_name);
	if (ret < 0) {
		__log_destroy_rename(log_rename);
		return ret;
	}

	ret = __log_create_file(&log_rename->new_location,
			&BTRFS_I(new_dir)->location, &new_d_inode->location,
			&new_dentry->d_name);
	if (ret < 0) {
		__log_destroy_rename(log_rename);
		return ret;
	}

	log_entry = __log_create_entry(snap, &new_d_inode->location,
			sizeof(*log_rename), log_rename, BTRFS_ACID_LOG_RENAME);
	if (IS_ERR(log_entry)) {
		__log_destroy_rename(log_rename);
		return PTR_ERR(log_entry);
	}
	BTRFS_SUB_DBG(LOG, "RENAME: Adding to write-log\n");
	list_add(&log_entry->list, &snap->write_log);

	/* A rename may affect two different parents. This is why we must log it
	 * into the two different parents in the CR-Log. If both parents are the
	 * same, then we will only log it once.
	 */
	ret = btrfs_acid_log_cr_insert(snap, log_entry,
			old_dir->i_ino, old_dentry->d_inode->i_ino);
	if (ret < 0) {
		BTRFS_SUB_DBG(LOG, "RENAME: Error logging to CRL (parent = %llu)\n",
				old_dir->i_ino);
	}

	if (old_dir->i_ino != new_dir->i_ino) {
		ret = btrfs_acid_log_cr_insert(snap, log_entry,
				new_dir->i_ino, new_dentry->d_inode->i_ino);
		if (ret < 0) {
			BTRFS_SUB_DBG(LOG, "RENAME: Error logging to CRL "
					"(parents: old = %llu, new = %llu)\n",
					old_dir->i_ino, new_dir->i_ino);
		}
	}
#endif

	return 0;
}

int btrfs_acid_log_symlink(struct inode * dir, struct dentry * dentry,
		const char * symname)
{
	struct btrfs_acid_snapshot * snap;
//	struct btrfs_acid_log_entry * log_entry;
	struct btrfs_acid_log_symlink * log_symlink;
	struct btrfs_inode * parent, * inode;
	struct qstr * name;
	int ret = 0;

	if (!dir || !dentry || !dentry->d_inode || !symname)
		return -EINVAL;

	parent = BTRFS_I(dir);
	inode = BTRFS_I(dentry->d_inode);
	name = &dentry->d_name;

	snap = BTRFS_I(dir)->root->snap;

	log_symlink = __log_create_symlink(parent, inode, name, symname);
	if (IS_ERR(log_symlink))
		return PTR_ERR(log_symlink);

	ret = __log_op_add(snap, log_symlink, inode->location.objectid,
			BTRFS_ACID_LOG_SYMLINK);
	if (ret < 0) {
		__log_destroy_symlink(log_symlink);
		return ret;
	}

#if 0
	log_symlink = __log_create_symlink(symname);
	if (IS_ERR(log_symlink))
		return PTR_ERR(log_symlink);

	ret = __log_create_file(&log_symlink->location, &BTRFS_I(dir)->location,
			&BTRFS_I(dentry->d_inode)->location, &dentry->d_name);
	if (ret < 0) {
		__log_destroy_symlink(log_symlink);
		return ret;
	}

	log_entry = __log_create_entry(snap, &BTRFS_I(dentry->d_inode)->location,
			sizeof(*log_symlink), log_symlink, BTRFS_ACID_LOG_SYMLINK);
	if (IS_ERR(log_entry)) {
		__log_destroy_symlink(log_symlink);
		return PTR_ERR(log_entry);
	}
	BTRFS_SUB_DBG(LOG, "SYMLINK: Adding to write-log\n");
	list_add(&log_entry->list, &snap->write_log);

	/* Similarly to the link operation, this operation will only affect the
	 * parent of the target symlink inode; therefore, we only log it once.
	 */
	ret = btrfs_acid_log_cr_insert(snap, log_entry,
			dir->i_ino, dentry->d_inode->i_ino);
	if (ret < 0) {
		BTRFS_SUB_DBG(LOG, "SYMLINK: Error logging to CRL\n");
	}
#endif

	return 0;
}

int btrfs_acid_log_setattr(struct dentry * dentry, struct iattr * attr)
{
//	struct btrfs_acid_log_entry * log_entry;
	struct btrfs_acid_log_attr * log_attr;
	struct btrfs_inode * parent, * inode;
	struct qstr * name;
	int err;

	if (!dentry || !dentry->d_inode || !attr)
		return -EINVAL;

	parent = BTRFS_I(dentry->d_parent->d_inode);
	inode = BTRFS_I(dentry->d_inode);
	name = &dentry->d_name;

	log_attr = __log_create_attr(parent, inode, name, attr->ia_valid);
	if (IS_ERR(log_attr))
		return PTR_ERR(log_attr);

	err = __log_op_add(inode->root->snap, log_attr, inode->location.objectid,
			BTRFS_ACID_LOG_ATTR_SET);
	if (err < 0) {
		__log_destroy_attr(log_attr);
		return err;
	}

#if 0
	inode = BTRFS_I(dentry->d_inode);
	log_entry = __log_create_entry(inode->root->snap, &inode->location,
			sizeof(*log_attr), log_attr, BTRFS_ACID_LOG_ATTR_SET);
	if (IS_ERR(log_entry)) {
		__log_destroy_attr(log_attr);
		return PTR_ERR(log_entry);
	}
	BTRFS_SUB_DBG(LOG, "SET-ATTR: Adding to write-log\n");
	list_add(&log_entry->list, &inode->root->snap->write_log);
#endif

	return 0;
}

int btrfs_acid_log_mknod(struct inode * dir, struct dentry * dentry,
		int mode, dev_t rdev)
{
	struct btrfs_acid_snapshot * snap;
	struct btrfs_acid_log_mknod * log_mknod;
//	struct btrfs_acid_log_entry * log_entry;
	struct btrfs_inode * parent, * inode;
	struct qstr * name;
	int ret = 0;

	if (!dir || !dentry || !dentry->d_inode)
		return -EINVAL;

	parent = BTRFS_I(dir);
	inode = BTRFS_I(dentry->d_inode);
	name = &dentry->d_name;

	snap = BTRFS_I(dir)->root->snap;

	log_mknod = __log_create_mknod(parent, inode, name, mode, rdev);
	if (IS_ERR(log_mknod))
		return PTR_ERR(log_mknod);

	ret = __log_op_add(snap, log_mknod, inode->location.objectid,
			BTRFS_ACID_LOG_MKNOD);
	if (ret < 0) {
		__log_destroy_mknod(log_mknod);
		return ret;
	}


#if 0
	log_mknod = __log_create_mknod(mode, rdev);
	if (IS_ERR(log_mknod))
		return PTR_ERR(log_mknod);

	ret = __log_create_file(&log_mknod->location, &BTRFS_I(dir)->location,
			&BTRFS_I(dentry->d_inode)->location, &dentry->d_name);
	if (ret < 0) {
		__log_destroy_mknod(log_mknod);
		return ret;
	}

	log_entry = __log_create_entry(snap, &BTRFS_I(dentry->d_inode)->location,
			sizeof(*log_mknod), log_mknod, BTRFS_ACID_LOG_MKNOD);
	if (IS_ERR(log_entry)) {
		__log_destroy_mknod(log_mknod);
		return PTR_ERR(log_entry);
	}
	BTRFS_SUB_DBG(LOG, "MKNOD: Adding to write-log\n");
	list_add(&log_entry->list, &snap->write_log);

	ret = btrfs_acid_log_cr_insert(snap, log_entry,
			dir->i_ino, dentry->d_inode->i_ino);
	if (ret < 0) {
		BTRFS_SUB_DBG(LOG, "MKNOD: Error logging to CRL\n");
	}
#endif

	return 0;
}

int btrfs_acid_log_setxattr(struct dentry * dentry, const char * name,
		const void * value, size_t size, int flags)
{
//	struct btrfs_acid_log_entry * log_entry;
	struct btrfs_acid_log_xattr * log_xattr;
	struct btrfs_inode * parent, * inode;
	struct qstr * d_name;
	int err;

	if (!dentry || !dentry->d_inode || !name || !value)
		return -EINVAL;

	parent = BTRFS_I(dentry->d_parent->d_inode);
	inode = BTRFS_I(dentry->d_inode);
	d_name = &dentry->d_name;

	log_xattr = __log_create_xattr(parent, inode, d_name,
			name, value, size, flags);
	if (IS_ERR(log_xattr))
		return PTR_ERR(log_xattr);

	err = __log_op_add(inode->root->snap, log_xattr, inode->location.objectid,
			BTRFS_ACID_LOG_XATTR_SET);
	if (err < 0) {
		__log_destroy_xattr(log_xattr);
		return err;
	}

#if 0
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
#endif

	return 0;
}

int btrfs_acid_log_getxattr(struct dentry * dentry, const char * name)
{
//	struct btrfs_acid_log_entry * log_entry;
	struct btrfs_acid_log_xattr * log_xattr;
	struct btrfs_inode * inode, * parent;
	struct qstr * d_name;
	int err;

	if (!dentry || !dentry->d_inode || !name)
		return -EINVAL;

	parent = BTRFS_I(dentry->d_parent->d_inode);
	inode = BTRFS_I(dentry->d_inode);
	d_name = &dentry->d_name;

	log_xattr = __log_create_xattr(parent, inode, d_name, name, NULL, 0, 0);
	if (IS_ERR(log_xattr))
		return PTR_ERR(log_xattr);

	err = __log_op_add(inode->root->snap, log_xattr, inode->location.objectid,
			BTRFS_ACID_LOG_XATTR_GET);
	if (err < 0) {
		__log_destroy_xattr(log_xattr);
		return err;
	}
#if 0
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
#endif

	return 0;
}

int btrfs_acid_log_listxattr(struct dentry * dentry,
		char * buffer, size_t user_size, ssize_t real_size)
{
	struct btrfs_acid_log_xattr * log_xattr;
//	struct btrfs_acid_log_entry * log_entry;
	struct btrfs_inode * parent, * inode;
	struct qstr * d_name;
	char * ptr, * attr_name;
	size_t missing;
	int err;

	if (!dentry || !dentry->d_inode)
		return -EINVAL;

	parent = BTRFS_I(dentry->d_parent->d_inode);
	inode = BTRFS_I(dentry->d_inode);
	d_name = &dentry->d_name;

	missing = (user_size <= real_size ? user_size : real_size);
	ptr = buffer;
	while (1) {
		attr_name = ptr;
		for (; ptr && *(ptr++); );
		missing -= (ptr - attr_name);

		log_xattr = __log_create_xattr(parent, inode, d_name,
				attr_name, NULL, 0, 0);
		if (IS_ERR(log_xattr))
			return PTR_ERR(log_xattr);

		err = __log_op_add(inode->root->snap, log_xattr,
				inode->location.objectid, BTRFS_ACID_LOG_XATTR_LIST);
		if (err < 0) {
			__log_destroy_xattr(log_xattr);
			return err;
		}

#if 0
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
#endif

		if (missing <= 0)
			break;
	}

	return 0;
}

int btrfs_acid_log_removexattr(struct dentry * dentry, const char * name)
{
//	struct btrfs_acid_log_entry * log_entry;
	struct btrfs_acid_log_xattr * log_xattr;
	struct btrfs_inode * parent, * inode;
	struct qstr * d_name;
	int err;

	if (!dentry || !dentry->d_inode || !name)
		return -EINVAL;

	parent = BTRFS_I(dentry->d_parent->d_inode);
	inode = BTRFS_I(dentry->d_inode);
	d_name = &dentry->d_name;

	log_xattr = __log_create_xattr(parent, inode, d_name, name, NULL, 0, 0);
	if (IS_ERR(log_xattr))
		return PTR_ERR(log_xattr);

	err = __log_op_add(inode->root->snap, log_xattr, inode->location.objectid,
			BTRFS_ACID_LOG_XATTR_REMOVE);
	if (err < 0) {
		__log_destroy_xattr(log_xattr);
		return err;
	}
#if 0
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
#endif

	return 0;
}

int btrfs_acid_log_truncate(struct inode * inode)
{
//	struct btrfs_acid_log_entry * log_entry;
	struct btrfs_acid_log_truncate * log_truncate;
	struct btrfs_inode * our_inode;
	int err;

	if (!inode)
		return -EINVAL;

	our_inode = BTRFS_I(inode);

	log_truncate =
			__log_create_truncate(&our_inode->location, inode->i_size);
	if (IS_ERR(log_truncate))
		return PTR_ERR(log_truncate);

	err = __log_op_add(our_inode->root->snap, log_truncate,
			our_inode->location.objectid, BTRFS_ACID_LOG_TRUNCATE);
	if (err < 0) {
		__log_destroy_truncate(log_truncate);
		return err;
	}

#if 0
	log_entry = __log_create_entry(BTRFS_I(inode)->root->snap,
			&BTRFS_I(inode)->location, sizeof(*log_truncate), log_truncate,
			BTRFS_ACID_LOG_TRUNCATE);
	if (IS_ERR(log_entry)) {
		kfree(log_truncate);
		return PTR_ERR(log_entry);
	}
	BTRFS_SUB_DBG(LOG, "TRUNCATE: Adding to write-log\n");
	list_add(&log_entry->list, &BTRFS_I(inode)->root->snap->write_log);
#endif

	return 0;
}

int btrfs_acid_log_permission(struct inode * inode, int mask)
{
//	struct btrfs_acid_log_entry * log_entry;
	struct btrfs_acid_log_permission * log_permission;
	struct btrfs_inode * our_inode;
	int err;

	if (!inode)
		return -EINVAL;

	our_inode = BTRFS_I(inode);

	log_permission = __log_create_permission(&our_inode->location, mask);
	if (IS_ERR(log_permission))
		return PTR_ERR(log_permission);

	err = __log_op_add(our_inode->root->snap, log_permission,
			our_inode->location.objectid, BTRFS_ACID_LOG_PERMISSION);
	if (err < 0) {
		__log_destroy_permission(log_permission);
		return err;
	}

#if 0
	log_entry = __log_create_entry(BTRFS_I(inode)->root->snap,
			&BTRFS_I(inode)->location, sizeof(*log_permission), log_permission,
			BTRFS_ACID_LOG_PERMISSION);
	if (IS_ERR(log_entry)) {
		kfree(log_permission);
		return PTR_ERR(log_entry);
	}
	BTRFS_SUB_DBG(LOG, "PERMISSION: Adding to read-log\n");
	list_add(&log_entry->list, &BTRFS_I(inode)->root->snap->read_log);
#endif
	return 0;
}

int btrfs_acid_log_mmap(struct file * filp, struct vm_area_struct * vma)
{
//	struct btrfs_acid_log_entry * log_entry;
	struct btrfs_acid_log_mmap * log_mmap;
	struct dentry * file_dentry;
	struct btrfs_inode *parent, * inode;
	struct qstr * name;
	pgoff_t start, end;
	int err;

	if (!filp || !vma)
		return -EINVAL;

	file_dentry = fdentry(filp);
	parent = BTRFS_I(file_dentry->d_parent->d_inode);
	inode = BTRFS_I(file_dentry->d_inode);
	name = &file_dentry->d_name;

	start = vma->vm_pgoff;
	end = start + ((vma->vm_end - vma->vm_start - 1) >> PAGE_CACHE_SHIFT);

	log_mmap = __log_create_mmap(parent, inode, name, start, end,
			vma->vm_page_prot, vma->vm_flags);
	if (IS_ERR(log_mmap))
		return PTR_ERR(log_mmap);

	err = __log_op_add(inode->root->snap, log_mmap, inode->location.objectid,
			BTRFS_ACID_LOG_MMAP);
	if (err < 0) {
		__log_destroy_mmap(log_mmap);
		return err;
	}
#if 0
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
#endif

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
//	struct btrfs_acid_log_entry * log_entry;
	struct btrfs_acid_log_rw * rw_entry;
	struct dentry * file_dentry;
	struct btrfs_inode * parent, * inode;
	struct qstr * name;
	unsigned int nlink;
	int err;

	if (!vma || !vmf)
		return -EINVAL;

	file_dentry = fdentry(vma->vm_file);
	parent = BTRFS_I(file_dentry->d_parent->d_inode);
	inode = BTRFS_I(file_dentry->d_inode);
	name = &file_dentry->d_name;

	nlink = file_dentry->d_inode->i_nlink;

	rw_entry = __log_create_rw(parent, inode, name,
			vmf->pgoff, vmf->pgoff, nlink);
	if (IS_ERR(rw_entry))
		return PTR_ERR(rw_entry);

	err = __log_op_add(inode->root->snap, rw_entry, inode->location.objectid,
			BTRFS_ACID_LOG_WRITE);
	if (err < 0) {
		__log_destroy_rw(rw_entry);
		return err;
	}

#if 0
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
#endif

	return 0;
}

void btrfs_acid_log_ops_print(struct btrfs_acid_snapshot * snap)
{
	struct btrfs_acid_log_entry * entry;
	struct list_head * head;

	if (!snap)
		return;

	mutex_lock(&snap->op_log_mutex);

	BTRFS_SUB_DBG(LOG, "----------------------------------------------\n");
	BTRFS_SUB_DBG(LOG, "  Operations Log (%d)\n", snap->owner_pid);

	head = &snap->op_log;
	list_for_each_entry(entry, head, list) {
		BTRFS_SUB_DBG(LOG, "clock: %llu, ino: %llu, type: %s\n",
				entry->clock, entry->ino, __log_type_to_str(entry->type));
	}
	BTRFS_SUB_DBG(LOG, "----------------------------------------------\n");

	mutex_unlock(&snap->op_log_mutex);
}

#if 0
int btrfs_acid_log_purge(struct list_head * log, u64 ino, u64 start, u64 end)
{
	struct list_head * entry, * tmp_entry;
	struct btrfs_acid_log_entry * log_entry;

	list_for_each_safe(entry, tmp_entry, log) {
//	list_for_each_safe(entry, log, list) {
		log_entry = list_entry(entry, struct btrfs_acid_log_entry, list);

		if ((log_entry->location.objectid == ino)
				&& (log_entry->clock > start)
				&& (log_entry->clock < end)) {
			list_del(entry);
			__log_destroy_entry(log_entry);
		}
	}
	return 0;
}

/*
 * The following four methods have a single purpose: guarantee that each and
 * every semaphore is acquired and released in a predefined order, avoiding
 * deadlocks when all three semaphores need to be acquired.
 *
 */
static void __crl_down_read(struct btrfs_acid_cr_log * crl)
{
	down_read(&crl->parents_list_sem);
	down_read(&crl->parents_sem);
	down_read(&crl->inodes_sem);
}

static void __crl_up_read(struct btrfs_acid_cr_log * crl)
{
	up_read(&crl->inodes_sem);
	up_read(&crl->parents_sem);
	up_read(&crl->parents_list_sem);
}

static void __crl_down_write(struct btrfs_acid_cr_log * crl)
{
	down_write(&crl->parents_list_sem);
	down_write(&crl->parents_sem);
	down_write(&crl->inodes_sem);
}

static void __crl_up_write(struct btrfs_acid_cr_log * crl)
{
	up_write(&crl->inodes_sem);
	up_write(&crl->parents_sem);
	up_write(&crl->parents_list_sem);
}

/**
 * btrfs_acid_log_cr_insert - Inserts an entry into the CR-Log.
 * @parent: the inode of the parent's where the operation was issued.
 * @ino: the target inode of the issued operation.
 * @log_entry: the C/R log entry.
 *
 * This method will add the given entry to three different data structures:
 * 	- A tree containing all operations made on @parent.
 * 	- A tree containing all operations made on @ino.
 * 	- A list containing all the values of @parent already accessed.
 */
static int btrfs_acid_log_cr_insert(struct btrfs_acid_snapshot * snap,
		struct btrfs_acid_log_entry * log_entry, u64 parent, u64 ino)
{
	int ret = 0;
	struct btrfs_acid_cr_log * crl;
	struct btrfs_acid_log_cr_inode * parent_lst_entry;
	struct list_head * lst;
	struct btrfs_acid_log_cr_entry * crl_entry;
	int new_parent = 0;

	if (!snap || !log_entry)
		return -EINVAL;

	crl = &snap->cr_log;

	parent_lst_entry = kzalloc(sizeof(*parent_lst_entry), GFP_NOFS);
	if (!parent_lst_entry)
		return -ENOMEM;

	crl_entry = kzalloc(sizeof(*crl_entry), GFP_NOFS);
	if (!crl_entry) {
		kfree(parent_lst_entry);
		return -ENOMEM;
	}

	parent_lst_entry->ino = parent;
	crl_entry->entry = log_entry;

	__crl_down_write(crl);

//	BTRFS_SUB_DBG(CR_LOG, "Adding entry to parent tree\n");

	/* Check for the parent on the tree. If it does not exist, add a new list
	 * to its position and add its ino to the parent's list; in the end, just
	 * add the entry to the list in its tree position.
	 */
	lst = radix_tree_lookup(&crl->parents, parent);
	if (!lst) {
		lst = kzalloc(sizeof(*lst), GFP_NOFS);
		if (!lst) {
			ret = -ENOMEM;
			goto err_free_mem;
		}
		INIT_LIST_HEAD(lst);
		ret = radix_tree_insert(&crl->parents, parent, lst);
		if (ret) {
			kfree(lst);
			goto err_free_mem;
		}
		new_parent = 1;
	}
//	BTRFS_SUB_DBG(CR_LOG, "Adding entry to parents tree's list\n");
	list_add(&crl_entry->parent_list, lst);

	if (new_parent) {
//		BTRFS_SUB_DBG(CR_LOG, "New parent: adding to list\n");
		list_add(&parent_lst_entry->list, &crl->parents_list);
	}

	/* Check the inode on the tree. If it does not exist, add a new list to
	 * its position; in the end, add the entry to this list.
	 */
//	BTRFS_SUB_DBG(CR_LOG, "Adding entry to inodes tree\n");
	lst = radix_tree_lookup(&crl->inodes, ino);
	if (!lst) {
		lst = kzalloc(sizeof(*lst), GFP_NOFS);
		if (!lst) {
			ret = -ENOMEM;
			goto err_parent_list_del;
		}
		INIT_LIST_HEAD(lst);
		ret = radix_tree_insert(&crl->inodes, ino, lst);
		if (ret) {
			kfree(lst);
			goto err_parent_list_del;
		}
		crl_entry->original_inode = 1;
	}
//	BTRFS_SUB_DBG(CR_LOG, "Adding entry to inodes tree's list\n");
	list_add(&crl_entry->inode_list, lst);

up_sems:
	__crl_up_write(crl);

	if (!new_parent)
		kfree(parent_lst_entry);

	return ret;

err_parent_list_del:
	list_del(&crl_entry->parent_list);
	if (new_parent)
		list_del(&parent_lst_entry->list);
err_free_mem:
	kfree(crl_entry);
	kfree(parent_lst_entry);

	goto up_sems;
}

void btrfs_acid_log_cr_print(struct btrfs_acid_snapshot * snap)
{
	struct btrfs_acid_cr_log * crl;
	struct btrfs_acid_log_cr_inode * inode_lst_entry;
	struct btrfs_acid_log_cr_entry * cr_entry;
	struct btrfs_acid_log_entry * log_entry;
	struct list_head * parent_lst, * inodes_lst;
	struct list_head * tmp_lst;
//	struct qstr * entry_qstr;
	struct btrfs_acid_log_file * location;
	u64 parent_ino;
	int original_parent;
	int show_nlink = 0;

	if (!snap)
		return;

	crl = &snap->cr_log;

	BTRFS_SUB_DBG(CR_LOG, "----------------------------------------------\n");
	BTRFS_SUB_DBG(CR_LOG, "  Creation/Removal Log (%d)\n", snap->owner_pid);

	__crl_down_read(crl);

	if (list_empty(&crl->parents_list))
		goto out;

	list_for_each_entry_reverse(inode_lst_entry, &crl->parents_list, list) {
		parent_ino = inode_lst_entry->ino;
		parent_lst = radix_tree_lookup(&crl->parents, parent_ino);
		if (!parent_lst) {
			BTRFS_SUB_DBG(CR_LOG, "!! Parent = %llu is NULL\n", parent_ino);
			continue;
		}
		if (list_empty(parent_lst)) {
			BTRFS_SUB_DBG(CR_LOG, "!! Parent = %llu is EMPTY\n", parent_ino);
			continue;
		}

		tmp_lst = radix_tree_lookup(&crl->inodes, parent_ino);
		original_parent = (tmp_lst == NULL);
		BTRFS_SUB_DBG(CR_LOG, "Parent ino: %llu (%s original)\n",
				parent_ino, (original_parent ? "is" : "not"));

		list_for_each_entry_reverse(cr_entry, parent_lst, parent_list) {
			log_entry = cr_entry->entry;

			location = NULL;
			switch (log_entry->type) {
			case BTRFS_ACID_LOG_CREATE:
				location = &((struct btrfs_acid_log_create *)
						log_entry->data)->location;
				break;
			case BTRFS_ACID_LOG_MKDIR:
				location = &((struct btrfs_acid_log_mkdir *)
						log_entry->data)->location;
				break;
			case BTRFS_ACID_LOG_UNLINK:
				location = &((struct btrfs_acid_log_unlink *)
						log_entry->data)->location;
				show_nlink = 1;
				break;
			}


			BTRFS_SUB_DBG(CR_LOG,
					"\tino: %llu, type: %s, clock: %llu, name: %.*s, "
					"nlink: %s%*d "
					"(%s original)\n",
					log_entry->location.objectid,
					__log_type_to_str(log_entry->type),
					log_entry->clock,
					(location ? location->name.len : 0),
					(location ? (char *) location->name.name : (char *) ""),
					(show_nlink ? "" : "N/A"),
					(show_nlink ? 4 : 0), log_entry->nlink,
					(cr_entry->original_inode ? "is" : "not"));
		}
	}


out:
	__crl_up_read(crl);
	BTRFS_SUB_DBG(CR_LOG, "----------------------------------------------\n");
}
#endif

static struct btrfs_acid_log_mmap *
__log_create_mmap(struct btrfs_inode * parent, struct btrfs_inode * inode,
		struct qstr * name,
		pgoff_t start, pgoff_t end, pgprot_t prot, unsigned long flags)
{
	struct btrfs_acid_log_mmap * entry;
	int err;

	if (!parent || !inode || !name)
		return ERR_PTR(-EINVAL);

	entry = kzalloc(sizeof(*entry), GFP_NOFS);
	if (!entry)
		return ERR_PTR(-EINVAL);

	err = __log_create_file(&entry->file, &parent->location,
			&inode->location, name);
	if (err < 0) {
		kfree(entry);
		return ERR_PTR(err);
	}
	entry->first_page = start;
	entry->last_page = end;

#if 0
	__clone_keys(&entry->location, location);
	err = __clone_names(&entry->name, name);
	if (err < 0) {
		kfree(entry);
		return ERR_PTR(err);
	}

	entry->pages.first_page = start;
	entry->pages.last_page = end;
#endif
	entry->prot = prot;
	entry->flags = flags;

	return entry;
}

static void __log_destroy_mmap(struct btrfs_acid_log_mmap * entry)
{
	if (entry) {
		__log_destroy_file(&entry->file);
//		__free_name(&entry->name);
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

static void __log_destroy_permission(struct btrfs_acid_log_permission * entry)
{
	if (entry)
		kfree(entry);
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
static void __log_destroy_truncate(struct btrfs_acid_log_truncate * entry)
{
	if (entry)
		kfree(entry);
}

/* 'attr_name' may be NULL if, and only if, we are logging a 'listxattr' that
 * does not return attributes (i.e., that returns only the number of extended
 * attributes). In that case, 'value' must also be NULL.
 */
static struct btrfs_acid_log_xattr *
__log_create_xattr(struct btrfs_inode * parent, struct btrfs_inode * inode,
		struct qstr * name,
		const char * attr_name, const void * value, size_t size, int flags)
{
	int err;
	struct btrfs_acid_log_xattr * entry;
	struct qstr * qstr;

	if (!parent || !inode || !name)
		return ERR_PTR(-EINVAL);

	if (!attr_name && value)
		return ERR_PTR(-EINVAL);

	entry = kzalloc(sizeof(*entry), GFP_NOFS);
	if (!entry)
		return ERR_PTR(-ENOMEM);

	err = __log_create_file(&entry->file, &parent->location,
			&inode->location, name);
	if (err < 0)
		goto err_free;

#if 0
	__clone_keys(&entry->location, location);
	err = __clone_names(&entry->name, name);
	if (err < 0)
		goto err_free;

#endif
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
	__log_destroy_file(&entry->file);
err_free:
	kfree(entry);
	return ERR_PTR(err);
}

static void __log_destroy_xattr(struct btrfs_acid_log_xattr * entry)
{
	if (entry) {
//		__free_name(&entry->name);
		__log_destroy_file(&entry->file);
		__free_name(&entry->attr_name);
		if (entry->value)
			kfree(entry->value);
		kfree(entry);
	}
}

static struct btrfs_acid_log_mknod *
__log_create_mknod(struct btrfs_inode * parent, struct btrfs_inode * inode,
		struct qstr * name, int mode, dev_t rdev)
{
	int err;
	struct btrfs_acid_log_mknod * entry;

	if (!parent || !inode || !name)
		return ERR_PTR(-EINVAL);

	entry = kzalloc(sizeof(*entry), GFP_NOFS);
	if (!entry)
		return ERR_PTR(-ENOMEM);

	err = __log_create_file(&entry->file, &parent->location,
			&inode->location, name);
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
		__log_destroy_file(&entry->file);
		kfree(entry);
	}
}

static struct btrfs_acid_log_symlink *
__log_create_symlink(struct btrfs_inode * parent, struct btrfs_inode * inode,
		struct qstr * name, const char * symname)
{
	int err;
	struct btrfs_acid_log_symlink * entry;
	struct qstr * qstr;

	if (!symname)
		return ERR_PTR(-EINVAL);

	entry = kzalloc(sizeof(*entry), GFP_NOFS);
	if (!entry)
		return ERR_PTR(-ENOMEM);

	err = __log_create_file(&entry->file, &parent->location,
			&inode->location, name);
	if (err < 0) {
		kfree(entry);
		return ERR_PTR(err);
	}

	err = -ENOMEM;
	qstr = &entry->symname;
	qstr->len = strlen(symname);
	qstr->name = kzalloc(sizeof(*qstr->name) * qstr->len, GFP_NOFS);
	if (!qstr->name) {
		__log_destroy_file(&entry->file);
		kfree(entry);
		return ERR_PTR(err);
	}
	memcpy((void *) qstr->name, (void *) symname, qstr->len);
	qstr->hash = full_name_hash(qstr->name, qstr->len);

	return entry;
}

static void __log_destroy_symlink(struct btrfs_acid_log_symlink * entry)
{
	if (entry) {
		__log_destroy_file(&entry->file);
		__free_name(&entry->symname);
		kfree(entry);
	}
}

static struct btrfs_acid_log_rename *
__log_create_rename(struct btrfs_inode * old_parent,
		struct btrfs_inode * old_inode, struct qstr * old_name,
		struct btrfs_inode * new_parent, struct btrfs_inode * new_inode,
		struct qstr * new_name)
{
	int err;
	struct btrfs_acid_log_rename * entry;
	struct btrfs_key * new_inode_key = NULL;

	if (!old_parent || !old_inode || !old_name
			|| !new_parent || !new_name)
		return ERR_PTR(-EINVAL);

	entry = kzalloc(sizeof(*entry), GFP_NOFS);
	if (!entry)
		return ERR_PTR(-ENOMEM);

	err = __log_create_file(&entry->old_file, &old_parent->location,
			&old_inode->location, old_name);
	if (err < 0)
		goto err_free;

	/* if we are renaming to an existing name, then @new_inode should not be
	 * NULL thus we log its key; otherwise, we must log a NULL key.
	 */
	if (new_inode) {
		entry->unlinked_file = kzalloc(sizeof(*entry->unlinked_file), GFP_NOFS);
		if (!entry->unlinked_file)
			goto err_free_old;
		err = __log_create_file(entry->unlinked_file, &new_parent->location,
				&new_inode->location, new_name);
		if (err < 0) {
			kfree(entry->unlinked_file);
			goto err_free_old;
		}
		entry->unlinked_file_nlink = new_inode->vfs_inode.i_nlink;
	}

	err = __log_create_file(&entry->new_file, &new_parent->location,
			&old_inode->location, new_name);
//			new_inode_key, new_name);
	if (err < 0)
		goto err_free_unlinked_file;

	entry->nlink = old_inode->vfs_inode.i_nlink;

	return entry;

err_free_unlinked_file:
	if (new_inode) {
		__log_destroy_file(entry->unlinked_file);
		kfree(entry->unlinked_file);
	}
err_free_old:
	__log_destroy_file(&entry->old_file);
err_free:
	kfree(entry);
	return ERR_PTR(err);
}

static void __log_destroy_rename(struct btrfs_acid_log_rename * entry)
{
	if (entry) {
		__log_destroy_file(&entry->old_file);
		__log_destroy_file(&entry->new_file);
	}
}

static struct btrfs_acid_log_rmdir *
__log_create_rmdir(struct btrfs_inode * parent, struct btrfs_inode * inode,
		struct qstr * name)
{
	int err;
	struct btrfs_acid_log_rmdir * entry;

	if (!parent || !inode || !name)
		return ERR_PTR(-EINVAL);

	entry = kzalloc(sizeof(*entry), GFP_NOFS);
	if (!entry)
		return ERR_PTR(-ENOMEM);

	err = __log_create_file(&entry->file, &parent->location,
			&inode->location, name);
	if (err < 0) {
		kfree(entry);
		return ERR_PTR(err);
	}

	return entry;
}

static void __log_destroy_rmdir(struct btrfs_acid_log_rmdir * entry)
{
	if (entry) {
		__log_destroy_file(&entry->file);
		kfree(entry);
	}
}

static struct btrfs_acid_log_readdir *
__log_create_readdir(struct btrfs_inode * inode, struct qstr * name)
{
	int err;
	struct btrfs_acid_log_readdir * entry;

	if (!inode || !name)
		return ERR_PTR(-EINVAL);

	entry = kzalloc(sizeof(*entry), GFP_NOFS);
	if (!entry)
		return ERR_PTR(-ENOMEM);

	err = __log_create_file(&entry->file, NULL,
			&inode->location, name);
	if (err < 0) {
		kfree(entry);
		return ERR_PTR(err);
	}

	return entry;
}

static void __log_destroy_readdir(struct btrfs_acid_log_readdir * entry)
{
	if (entry) {
		__log_destroy_file(&entry->file);
		kfree(entry);
	}
}

static struct btrfs_acid_log_mkdir *
__log_create_mkdir(struct btrfs_inode * parent, struct btrfs_inode * inode,
		struct qstr * name, int mode)
{
	int err;
	struct btrfs_acid_log_mkdir * entry;

	if (!parent || !inode || !name)
		return ERR_PTR(-EINVAL);

	entry = kzalloc(sizeof(*entry), GFP_NOFS);
	if (!entry)
		return ERR_PTR(-ENOMEM);

	err = __log_create_file(&entry->file, &parent->location,
			&inode->location, name);
	if (err < 0) {
		kfree(entry);
		return ERR_PTR(err);
	}

	entry->mode = mode;

	return entry;
}

static void __log_destroy_mkdir(struct btrfs_acid_log_mkdir * entry)
{
	if (!entry)
		return;
	__log_destroy_file(&entry->file);
	kfree(entry);
}

static struct btrfs_acid_log_link *
__log_create_link(struct btrfs_inode * old_parent,
		struct btrfs_inode * old_inode, struct qstr * old_name,
		struct btrfs_inode * new_parent, struct btrfs_inode * new_inode,
		struct qstr * new_name, unsigned int inode_nlink)
{
	struct btrfs_acid_log_link * entry;
	int err;

	if (!old_parent || !old_inode || !old_name
			|| !new_parent || !new_inode || !new_name)
		return ERR_PTR(-EINVAL);

	entry = kzalloc(sizeof(*entry), GFP_NOFS);
	if (!entry)
		return ERR_PTR(-ENOMEM);

	err = __log_create_file(&entry->old_file, &old_parent->location,
			&old_inode->location, old_name);
	if (err < 0)
		goto err_free;

	err = __log_create_file(&entry->new_file, &new_parent->location,
			&new_inode->location, new_name);
	if (err < 0)
		goto err_free_old;

	entry->nlink = inode_nlink;

	return entry;

err_free_old:
	__log_destroy_file(&entry->old_file);
err_free:
	kfree(entry);
	return ERR_PTR(err);
}

static void __log_destroy_link(struct btrfs_acid_log_link * entry)
{
	if (!entry)
		return;

	__log_destroy_file(&entry->old_file);
	__log_destroy_file(&entry->new_file);
	kfree(entry);
}

static struct btrfs_acid_log_unlink *
__log_create_unlink(struct btrfs_inode * parent, struct btrfs_inode * inode,
		struct qstr * name, unsigned int nlink)
{
	struct btrfs_acid_log_unlink * log_entry;
	int err;

	if (!parent || !inode || !name)
		return ERR_PTR(-EINVAL);

	log_entry = kzalloc(sizeof(*log_entry), GFP_NOFS);
	if (!log_entry)
		return ERR_PTR(-ENOMEM);

	err = __log_create_file(&log_entry->file, &parent->location,
			&inode->location, name);
	if (err < 0) {
		kfree(log_entry);
		return ERR_PTR(err);
	}
	log_entry->nlink = nlink;

	return log_entry;
}

static void __log_destroy_unlink(struct btrfs_acid_log_unlink * entry)
{
	if (!entry)
		return;

	__log_destroy_file(&entry->file);

	kfree(entry);
}

/* Yes, this method name is h-o-r-r-i-b-l-e. But it creates a 'create' log
 * entry. I.e., when a 'creat()' is issued and we need to log it, we must
 * create a 'create' log entry, to guarantee the 'create' is logged. I could
 * go on... */
//static struct btrfs_acid_log_create * __log_create_create(int mode)
static struct btrfs_acid_log_create *
__log_create_create(struct btrfs_inode * parent, struct btrfs_inode * inode,
		struct qstr * name, int mode)
{
	struct btrfs_acid_log_create * log_entry;
//	struct qstr * ptr;
	int err = 0;

	if (!parent || !inode || !name)
		return ERR_PTR(-EINVAL);

	log_entry = kzalloc(sizeof(*log_entry), GFP_NOFS);
	if (!log_entry)
		return ERR_PTR(-ENOMEM);

	err = __log_create_file(&log_entry->file, &parent->location,
			&inode->location, name);
	if (err < 0) {
		kfree(log_entry);
		return ERR_PTR(err);
	}
	log_entry->mode = mode;

	return log_entry;
}

static void __log_destroy_create(struct btrfs_acid_log_create * entry)
{
	if (!entry)
		return;
	__log_destroy_file(&entry->file);
	kfree(entry);
}

static struct btrfs_acid_log_attr *
__log_create_attr(struct btrfs_inode * parent, struct btrfs_inode * inode,
		struct qstr * name, unsigned int flags)
{
	struct btrfs_acid_log_attr * entry;
	int err;

	if (!parent || !inode || !name)
		return ERR_PTR(-EINVAL);

	entry = kzalloc(sizeof(*entry), GFP_NOFS);
	if (!entry)
		return ERR_PTR(-ENOMEM);

#if 0
	inode = BTRFS_I(dentry->d_inode);
	__clone_keys(&entry->location, &inode->location);
	err = __clone_names(&entry->name, &dentry->d_name);
	if (err < 0) {
		kfree(entry);
		return ERR_PTR(err);
	}
#endif

	err = __log_create_file(&entry->file, &parent->location,
			&inode->location, name);
	if (err < 0) {
		kfree(entry);
		return ERR_PTR(err);
	}

	entry->flags = flags;

	return entry;
}

static void __log_destroy_attr(struct btrfs_acid_log_attr * entry)
{
	if (entry) {
		__log_destroy_file(&entry->file);
//		__free_name(&entry->name);
		kfree(entry);
	}
}

/*
 * Create a 'Read/Write' entry for the log. Both reads and writes share the
 * same attributes when it comes to logging, so we use the same struct for
 * both of them.
 */
static struct btrfs_acid_log_rw *
__log_create_rw(struct btrfs_inode * parent, struct btrfs_inode * inode,
		struct qstr * name,
		pgoff_t first, pgoff_t last, unsigned int nlink)
{
	struct btrfs_acid_log_rw * entry;
	int err;

	if (last < first)
		return ERR_PTR(-EINVAL);

	entry = kzalloc(sizeof(*entry), GFP_NOFS);
	if (!entry)
		return ERR_PTR(-ENOMEM);

	entry->first_page = first;
	entry->last_page = last;
	entry->nlink = nlink;

	err = __log_create_file(&entry->file, &parent->location,
			&inode->location, name);
	if (err < 0) {
		kfree(entry);
		return ERR_PTR(err);
	}

	return entry;
}

static void __log_destroy_rw(struct btrfs_acid_log_rw * entry)
{
	if (entry) {
		__log_destroy_file(&entry->file);
		kfree(entry);
	}
}

#if 0
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

/**
 * __log_destroy_entry - Destroys a Log Entry and its data by operation type.
 *
 * Destroys a log entry. Its data field is destroyed by calling the appropriate
 * destroy method, depending on the operation type.
 *
 * This method does not remove the element from any list. Such should be
 * done *before* calling this method.
 */
static void __log_destroy_entry(struct btrfs_acid_log_entry * entry)
{
	if (!entry)
		return;

	if (!entry->data)
		goto destroy_entry;

	switch (entry->type) {
	case BTRFS_ACID_LOG_ATTR_GET:
	case BTRFS_ACID_LOG_ATTR_SET:
		__log_destroy_attr(entry->data);
		break;
	case BTRFS_ACID_LOG_CREATE:
		__log_destroy_create(entry->data);
		break;
	case BTRFS_ACID_LOG_LINK:
		__log_destroy_link(entry->data);
		break;
	case BTRFS_ACID_LOG_MKDIR:
		__log_destroy_mkdir(entry->data);
		break;
	case BTRFS_ACID_LOG_MKNOD:
		__log_destroy_mknod(entry->data);
	case BTRFS_ACID_LOG_MMAP:
		__log_destroy_mmap(entry->data);
		break;
	case BTRFS_ACID_LOG_PERMISSION:
		__log_destroy_permission(entry->data);
		break;
	case BTRFS_ACID_LOG_READ:
	case BTRFS_ACID_LOG_WRITE:
		__log_destroy_rw(entry->data);
		break;
	case BTRFS_ACID_LOG_READDIR: /* no data defined */
		break;
	case BTRFS_ACID_LOG_RENAME:
		__log_destroy_rename(entry->data);
		break;
	case BTRFS_ACID_LOG_RMDIR:
		__log_destroy_rmdir(entry->data);
		break;
	case BTRFS_ACID_LOG_SYMLINK:
		__log_destroy_symlink(entry->data);
		break;
	case BTRFS_ACID_LOG_TRUNCATE:
		__log_destroy_truncate(entry->data);
		break;
	case BTRFS_ACID_LOG_UNLINK:
		__log_destroy_unlink(entry->data);
		break;
	case BTRFS_ACID_LOG_XATTR_GET:
	case BTRFS_ACID_LOG_XATTR_SET:
	case BTRFS_ACID_LOG_XATTR_REMOVE:
	case BTRFS_ACID_LOG_XATTR_LIST:
		__log_destroy_xattr(entry->data);
		break;
	}

destroy_entry:
	kfree(entry);
}
#endif

static int
__log_create_file(struct btrfs_acid_log_file * file,
		struct btrfs_key * parent, struct btrfs_key * location,
		struct qstr * name)
{
//	struct qstr * ptr;
	int ret = 0;

	if (!file)
		return -EINVAL;

	if (parent)
		btrfs_acid_copy_key(&file->parent_location, parent);
	if (location)
		btrfs_acid_copy_key(&file->location, location);

	if (name) {
		ret = btrfs_acid_copy_qstr(&file->name, name);
		if (ret < 0)
			BTRFS_SUB_DBG(LOG, "Error copying qstr's\n");
	}

	return ret;
}

static void
__log_destroy_file(struct btrfs_acid_log_file * file)
{
	if (!file)
		return;
	__free_name(&file->name);
}

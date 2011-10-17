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
#ifndef __BTRFS_TXBTRFS_LOG__
#define __BTRFS_TXBTRFS_LOG__
#include <linux/slab.h>
#include <linux/list.h>
#include "ctree.h"
#include "txbtrfs.h"

#if 0
#define BTRFS_ACID_LOG_READ				(1 << 0)
#define BTRFS_ACID_LOG_WRITE			(1 << 1)
#define BTRFS_ACID_LOG_ATTR_GET			(1 << 2)
#define BTRFS_ACID_LOG_ATTR_SET			(1 << 3)
#define BTRFS_ACID_LOG_READDIR			(1 << 4)
#define BTRFS_ACID_LOG_CREATE			(1 << 5)
#define BTRFS_ACID_LOG_UNLINK			(1 << 6)
#define BTRFS_ACID_LOG_LINK				(1 << 7)
#define BTRFS_ACID_LOG_MKDIR			(1 << 8)
#define BTRFS_ACID_LOG_RMDIR			(1 << 9)
#define BTRFS_ACID_LOG_RENAME			(1 << 10)
#define BTRFS_ACID_LOG_SYMLINK			(1 << 11)
#define BTRFS_ACID_LOG_MKNOD			(1 << 12)
#define BTRFS_ACID_LOG_XATTR_SET		(1 << 13)
#define BTRFS_ACID_LOG_XATTR_GET		(1 << 14)
#define BTRFS_ACID_LOG_XATTR_LIST		(1 << 15)
#define BTRFS_ACID_LOG_XATTR_REMOVE		(1 << 16)
#define BTRFS_ACID_LOG_TRUNCATE			(1 << 17)
#define BTRFS_ACID_LOG_PERMISSION		(1 << 18)
#define BTRFS_ACID_LOG_MMAP				(1 << 19)
#else
#define BTRFS_ACID_LOG_READ				1
#define BTRFS_ACID_LOG_WRITE			2
#define BTRFS_ACID_LOG_ATTR_GET			3
#define BTRFS_ACID_LOG_ATTR_SET			4
#define BTRFS_ACID_LOG_READDIR			5
#define BTRFS_ACID_LOG_CREATE			6
#define BTRFS_ACID_LOG_UNLINK			7
#define BTRFS_ACID_LOG_LINK				8
#define BTRFS_ACID_LOG_MKDIR			9
#define BTRFS_ACID_LOG_RMDIR			10
#define BTRFS_ACID_LOG_RENAME			11
#define BTRFS_ACID_LOG_SYMLINK			12
#define BTRFS_ACID_LOG_MKNOD			13
#define BTRFS_ACID_LOG_XATTR_SET		14
#define BTRFS_ACID_LOG_XATTR_GET		15
#define BTRFS_ACID_LOG_XATTR_LIST		16
#define BTRFS_ACID_LOG_XATTR_REMOVE		17
#define BTRFS_ACID_LOG_TRUNCATE			18
#define BTRFS_ACID_LOG_PERMISSION		19
#define BTRFS_ACID_LOG_MMAP				20
#endif


/**
 * btrfs_acid_log_file - keep a parent's and the inode's location and name.
 *
 * Of those operations logging names and locations, all of them, in some form
 * and shape, log these fields. We're just making it easier to access them in
 * a predefined way.
 */
struct btrfs_acid_log_file
{
	struct btrfs_key parent_location;
	struct btrfs_key location;
	struct qstr name;
};

struct btrfs_acid_log_entry
{
	struct list_head list;
	u64 clock;
	u64 ino;
	u16 type;

#if 0
	struct btrfs_key location;
	u64 clock;
	u16 type;
	u64 dirid;
	/* only applicable to those operations requiring to know
	 * how many nlinks an inode has.
	 */
	unsigned int nlink;

	struct list_head list;

	size_t size;
	void * data;
#endif
};

struct btrfs_acid_log_rw
{
	struct list_head list;
	u64 clock;
	u64 ino;
	u16 type;

	struct btrfs_acid_log_file file;
	pgoff_t first_page;
	pgoff_t last_page;
	unsigned int nlink;
};

struct btrfs_acid_log_attr
{
	struct list_head list;
	u64 clock;
	u64 ino;
	u16 type;

	struct btrfs_acid_log_file file;
	unsigned long flags;
#if 0
	struct btrfs_key location;
	struct qstr name;
#endif
};

struct btrfs_acid_log_create
{
	struct list_head list;
	u64 clock;
	u64 ino;
	u16 type;

	struct btrfs_acid_log_file file;
	int mode;
};

struct btrfs_acid_log_unlink
{
	struct list_head list;
	u64 clock;
	u64 ino;
	u16 type;

	struct btrfs_acid_log_file file;
	unsigned int nlink;
};

struct btrfs_acid_log_link
{
	struct list_head list;
	u64 clock;
	u64 ino;
	u16 type;

	struct btrfs_acid_log_file old_file;
	struct btrfs_acid_log_file new_file;
	unsigned int nlink;

	/* original inode location */
//	struct btrfs_key old_location;
//	struct qstr old_name;
//	/* new inode location */
//	struct btrfs_key new_location;
//	struct qstr new_name;
};

struct btrfs_acid_log_mkdir
{
	/* created dentry's inode location */
//	struct btrfs_key location;
//	/* created dentry's name */
//	struct qstr name;

	struct list_head list;
	u64 clock;
	u64 ino;
	u16 type;

	struct btrfs_acid_log_file file;
	int mode;
};

struct btrfs_acid_log_rmdir
{
	/* removed dentry's inode location */
//	struct btrfs_key location;
//	/* removed dentry's name */
//	struct qstr name;
	struct list_head list;
	u64 clock;
	u64 ino;
	u16 type;

	struct btrfs_acid_log_file file;
};

struct btrfs_acid_log_readdir
{
	struct list_head list;
	u64 clock;
	u64 ino;
	u16 type;

	struct btrfs_acid_log_file file;
};

struct btrfs_acid_log_rename
{
	/* old inode's parent location before being renamed */
//	struct btrfs_key old_location;
//	/* old name before being renamed */
//	struct qstr old_name;
//	/* new inode's parent location after being renamed */
//	struct btrfs_key new_location;
//	/* new name after being renamed */
//	struct qstr new_name;
	struct list_head list;
	u64 clock;
	u64 ino;
	u16 type;

	struct btrfs_acid_log_file old_file;
	struct btrfs_acid_log_file new_file;
	unsigned int nlink;

	struct btrfs_acid_log_file * unlinked_file;
	unsigned int unlinked_file_nlink;
};

struct btrfs_acid_log_symlink
{
	/* new symlink inode's parent location */
//	struct btrfs_key parent_location;
//	/* new symlink's name */
//	struct qstr name;
//	/* new symlink inode's location */
//	struct btrfs_key location;
	struct list_head list;
	u64 clock;
	u64 ino;
	u16 type;

	struct btrfs_acid_log_file file;
	/* name the symlink points to */
	struct qstr symname;
};

struct btrfs_acid_log_mknod
{
//	struct btrfs_key parent_location;
//	struct qstr name;
//	struct btrfs_key location;
	struct list_head list;
	u64 clock;
	u64 ino;
	u16 type;

	struct btrfs_acid_log_file file;
	int mode;
	dev_t rdev;
};

struct btrfs_acid_log_xattr
{
	struct list_head list;
	u64 clock;
	u64 ino;
	u16 type;

	struct btrfs_acid_log_file file;
#if 0
	struct btrfs_key location;
	struct qstr name;
#endif
	struct qstr attr_name;
	void * value;
	size_t size;
	int flags;
};

struct btrfs_acid_log_truncate
{
	struct list_head list;
	u64 clock;
	u64 ino;
	u16 type;

	struct btrfs_acid_log_file file;
//	struct btrfs_key location;
//	loff_t size;
	pgoff_t from;
};

struct btrfs_acid_log_permission
{
	struct list_head list;
	u64 clock;
	u64 ino;
	u16 type;

	struct btrfs_key location;
	int mask;
};

struct btrfs_acid_log_mmap
{
	struct list_head list;
	u64 clock;
	u64 ino;
	u16 type;

	/* analogous to btrfs_acid_log_rw */
	struct btrfs_acid_log_file file;
	pgoff_t first_page;
	pgoff_t last_page;

//	struct btrfs_key location;
//	struct qstr name;

	pgprot_t prot;
	unsigned long flags;

//	pgoff_t first_page;
//	pgoff_t last_page;
};

/**
 * struct btrfs_acid_log_cr_inode - Holds a inode value in a list.
 *
 * This may very well be overkill, but it is useful and we have no idea on how
 * to do this in a simpler way.
 */
struct btrfs_acid_log_cr_inode {
	u64 ino;
	struct list_head list;
};

/**
 * struct btrfs_acid_log_cr_entry - Maps a log entry on both CR-log lists.
 */
struct btrfs_acid_log_cr_entry {
	struct btrfs_acid_log_entry * entry;
	/* marks if the inode being operated on is from the original txsv */
	int original_inode;

	struct list_head inode_list;
	struct list_head parent_list;
};

char * btrfs_acid_log_type_to_str(u16 type);

int btrfs_acid_log_read(struct btrfs_inode * parent, struct btrfs_inode * inode,
		struct qstr * name, pgoff_t first, pgoff_t last);
int btrfs_acid_log_write(struct btrfs_inode * parent,
		struct btrfs_inode * inode, struct qstr * name,
		pgoff_t first, pgoff_t last);
//int btrfs_acid_log_getattr(struct inode * inode);
int btrfs_acid_log_getattr(struct dentry * dentry);
int btrfs_acid_log_readdir(struct file * filp);
int btrfs_acid_log_create(struct inode * dir, struct dentry * dentry, int mode);
int btrfs_acid_log_unlink(struct inode * dir, struct dentry * dentry);
int btrfs_acid_log_link(struct dentry * old_dentry, struct inode * dir,
		struct dentry * new_dentry);
int btrfs_acid_log_mkdir(struct inode * dir, struct dentry * dentry, int mode);
int btrfs_acid_log_rmdir(struct inode * dir, struct dentry * dentry);
int btrfs_acid_log_rename(struct inode * old_dir, struct dentry * old_dentry,
		struct inode * new_dir, struct dentry * new_dentry);
int btrfs_acid_log_symlink(struct inode * dir, struct dentry * dentry,
		const char * symname);
int btrfs_acid_log_setattr(struct dentry * dentry, struct iattr * attr);
int btrfs_acid_log_mknod(struct inode * dir, struct dentry * dentry,
		int mode, dev_t rdev);
int btrfs_acid_log_setxattr(struct dentry * dentry, const char * name,
		const void * value, size_t size, int flags);
int btrfs_acid_log_getxattr(struct dentry * dentry, const char * name);
int btrfs_acid_log_listxattr(struct dentry * dentry,
		char * buffer, size_t user_size, ssize_t real_size);
int btrfs_acid_log_removexattr(struct dentry * dentry, const char * name);
int btrfs_acid_log_truncate(struct inode * inode);
int btrfs_acid_log_permission(struct inode * inode, int mask);
int btrfs_acid_log_mmap(struct file * filp, struct vm_area_struct * vma);
int btrfs_acid_log_page_mkwrite(struct vm_area_struct * vma,
		struct vm_fault * vmf);


void btrfs_acid_log_cr_print(struct btrfs_acid_snapshot * snap);
void btrfs_acid_log_ops_print(struct btrfs_acid_snapshot * snap);
int btrfs_acid_log_prune(struct btrfs_acid_snapshot * snap);

static inline void __clone_keys(struct btrfs_key * dst, struct btrfs_key * src)
{
	BUG_ON(!dst || !src);

	dst->objectid = src->objectid;
	dst->type = src->type;
	dst->offset = src->offset;
}

static inline int __clone_names(struct qstr * dst, struct qstr * src)
{
	BUG_ON(!dst || !src);
	BUG_ON(!src->name || !src->len);

	dst->len = src->len;
	dst->hash = src->hash;
	dst->name = kzalloc(sizeof(*dst->name) * dst->len, GFP_NOFS);
	if (!dst->name)
		return -ENOMEM;
	memcpy((void *) dst->name, src->name, dst->len);
	return 0;
}

static inline void __free_name(struct qstr * qstr)
{
	BUG_ON(!qstr);
	if (qstr->name) {
		kfree(qstr->name);
		qstr->name = NULL;
	}
}

#endif /* __BTRFS_TXBTRFS_LOG__ */

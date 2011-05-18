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

#define BTRFS_ACID_LOG_READ			(1 << 0)
#define BTRFS_ACID_LOG_WRITE		(1 << 1)
#define BTRFS_ACID_LOG_ATTR_GET		(1 << 2)
#define BTRFS_ACID_LOG_ATTR_SET		(1 << 3)
#define BTRFS_ACID_LOG_READDIR		(1 << 4)
#define BTRFS_ACID_LOG_CREATE		(1 << 5)
#define BTRFS_ACID_LOG_UNLINK		(1 << 6)
#define BTRFS_ACID_LOG_LINK			(1 << 7)
#define BTRFS_ACID_LOG_MKDIR		(1 << 8)
#define BTRFS_ACID_LOG_RMDIR		(1 << 9)
#define BTRFS_ACID_LOG_RENAME		(1 << 10)
#define BTRFS_ACID_LOG_SYMLINK		(1 << 11)
#define BTRFS_ACID_LOG_SYMLINK		(1 << 12)
#define BTRFS_ACID_LOG_MKNOD		(1 << 13)

struct btrfs_acid_log_entry
{
	struct btrfs_key location;
	u64 clock;
	u16 type;
	size_t size;
	void * data;

	struct list_head list;
};

struct btrfs_acid_log_rw
{
	pgoff_t first_page;
	pgoff_t last_page;
};

struct btrfs_acid_log_attr_rw
{
	struct btrfs_key location;
	struct qstr name;
	unsigned long flags;
};

struct btrfs_acid_log_create
{
	/* created inode location */
	struct btrfs_key location;
	struct qstr name;
	int mode;
};

struct btrfs_acid_log_unlink
{
	/* unlinked inode location */
	struct btrfs_key location;
	struct qstr name;
};

struct btrfs_acid_log_link
{
	/* original inode location */
	struct btrfs_key old_location;
	struct qstr old_name;
	/* new inode location */
	struct btrfs_key new_location;
	struct qstr new_name;
};

struct btrfs_acid_log_mkdir
{
	/* created dentry's inode location */
	struct btrfs_key location;
	/* created dentry's name */
	struct qstr name;
	int mode;
};

struct btrfs_acid_log_rmdir
{
	/* removed dentry's inode location */
	struct btrfs_key location;
	/* removed dentry's name */
	struct qstr name;
};

struct btrfs_acid_log_rename
{
	/* old inode's parent location before being renamed */
	struct btrfs_key old_location;
	/* old name before being renamed */
	struct qstr old_name;
	/* new inode's parent location after being renamed */
	struct btrfs_key new_location;
	/* new name after being renamed */
	struct qstr new_name;
};

struct btrfs_acid_log_symlink
{
	/* new symlink inode's parent location */
	struct btrfs_key parent_location;
	/* new symlink's name */
	struct qstr name;
	/* new symlink inode's location */
	struct btrfs_key location;
	/* name the symlink points to */
	struct qstr symname;
};

struct btrfs_acid_log_mknod
{
	struct btrfs_key parent_location;
	struct qstr name;
	struct btrfs_key location;
	int mode;
	dev_t rdev;
};

int btrfs_acid_log_read(struct btrfs_acid_snapshot * snap,
		struct btrfs_key * location, pgoff_t first, pgoff_t last);
int btrfs_acid_log_write(struct btrfs_acid_snapshot * snap,
		struct btrfs_key * location, pgoff_t first, pgoff_t last);
//int btrfs_acid_log_getattr(struct inode * inode);
int btrfs_acid_log_getattr(struct dentry * dentry);
int btrfs_acid_log_readdir(struct inode * inode);
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

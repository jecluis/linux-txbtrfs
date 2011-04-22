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
#ifndef __BTRFS_TXBTRFS__
#define __BTRFS_TXBTRFS__

#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/dcache.h>
#include "ioctl.h"
#include "ctree.h"

struct btrfs_key;
struct btrfs_root;
struct btrfs_fs_info;
struct btrfs_trans_handle;

/* txbtrfs specific structs */
struct btrfs_acid_snapshot
{
	struct btrfs_root * root;
	struct btrfs_key * location; /* may be null if 'root' != null */
	struct btrfs_key * src_location;
	struct qstr path;
	unsigned long long hash;
	u64 gen;
	pid_t owner_pid;
	u64 parent_ino;
	u64 dir_index;
};

/* struct btrfs_acid_ctl, to be kept as a field in 'struct btrfs_fs_info',
 * as a control point for all things related to txbtrfs. */
struct btrfs_acid_ctl
{
	struct rw_semaphore sv_sem;
	struct btrfs_acid_snapshot * sv;

	struct rw_semaphore curr_snaps_sem;
	struct radix_tree_root current_snapshots;
};



/* Debug macros */
#define BTRFS_TX_PRINT(type, prefix, fmt, args...) \
	printk(type "[" prefix "] " fmt, ## args)

#define BTRFS_TX_DEBUG(fmt, args...) \
	BTRFS_TX_PRINT(KERN_DEBUG, "DEBUG", fmt, ## args)
#define BTRFS_TX_WARN(fmt, args...)  \
	BTRFS_TX_PRINT(KERN_WARNING, "WARN", fmt, ## args)
#define BTRFS_TX_INFO(fmt, args...)  \
	BTRFS_TX_PRINT(KERN_INFO, "INFO", fmt, ## args)

#define BTRFS_TX_DBG(prefix, fmt, args...) \
	printk(KERN_DEBUG "<TX> %s: " fmt, prefix, ## args)

/* external methods */
int btrfs_acid_init(struct btrfs_fs_info * fs_info);

int btrfs_acid_tx_start(struct file * file);
int btrfs_acid_change_root(struct file * file,
		struct btrfs_ioctl_acid_change_root_args * args);
struct btrfs_acid_snapshot *
btrfs_acid_create_snapshot(struct dentry * txsv_dentry);
int btrfs_acid_create_snapshot_by_ioctl(struct file * file,
		struct btrfs_ioctl_acid_create_snapshot_args * args);
int btrfs_insert_snapshot_item(struct btrfs_trans_handle * trans,
		struct btrfs_root * tree_root, struct btrfs_key * src_key,
		struct btrfs_key * snap_key,
		u64 dir, struct dentry * dentry, u64 dir_index);
int btrfs_acid_file_open(struct inode * inode, struct file * file);
int btrfs_acid_set_tx_subvol(struct file * file,
		struct btrfs_ioctl_acid_subvol_flags_args * args);
int btrfs_acid_d_hash(struct dentry * dentry, struct qstr * str);
int btrfs_acid_d_revalidate(struct dentry * dentry, struct nameidata * nd);
int btrfs_is_acid_subvol(struct btrfs_root * root);

/* inline methods */
static inline int btrfs_acid_tx_commit(void) { return -EOPNOTSUPP; }
static inline int btrfs_acid_tx_abort(void) {return -EOPNOTSUPP; }

static inline struct btrfs_acid_snapshot *
btrfs_acid_current_snapshot(struct btrfs_acid_ctl * ctl)
{
	struct btrfs_acid_snapshot * snap;

	down_read(&ctl->curr_snaps_sem);
	snap = radix_tree_lookup(&ctl->current_snapshots, current->pid);
	up_read(&ctl->curr_snaps_sem);

	return snap;
}

#endif /* __BTRFS_TXBTRFS__ */

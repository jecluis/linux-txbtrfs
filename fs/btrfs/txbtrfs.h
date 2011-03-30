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
#include "ioctl.h"

/* Debug macros */
#define BTRFS_TX_PRINT(type, prefix, fmt, args...) \
	printk(type "[" prefix "] " fmt, ## args)

#define BTRFS_TX_DEBUG(fmt, args...) \
	BTRFS_TX_PRINT(KERN_DEBUG, "DEBUG", fmt, ## args)
#define BTRFS_TX_WARN(fmt, args...)  \
	BTRFS_TX_PRINT(KERN_WARNING, "WARN", fmt, ## args)
#define BTRFS_TX_INFO(fmt, args...)  \
	BTRFS_TX_PRINT(KERN_INFO, "INFO", fmt, ## args)


int btrfs_acid_tx_start(struct file * file);
int btrfs_acid_change_root(struct file * file,
		struct btrfs_ioctl_acid_change_root_args * args);
int btrfs_acid_create_snapshot(struct file * file,
		struct btrfs_ioctl_acid_create_snapshot_args * args);
int btrfs_insert_snapshot_item(struct btrfs_trans_handle * trans,
		struct btrfs_root * tree_root, struct btrfs_key * src_key,
		struct btrfs_key * snap_key);
int btrfs_acid_file_open(struct inode * inode, struct file * file);
int btrfs_acid_subvol_flags(struct file * file,
		struct btrfs_ioctl_acid_subvol_flags_args * args);
int btrfs_acid_d_hash(struct dentry * dentry, struct qstr * str);

static inline int btrfs_acid_tx_commit(void) { return -EOPNOTSUPP; }
static inline int btrfs_acid_tx_abort(void) {return -EOPNOTSUPP; }

#endif /* __BTRFS_TXBTRFS__ */

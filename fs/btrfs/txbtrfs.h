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

/* Debug macros */
#define BTRFS_TX_PRINT(type, prefix, str) printk(type "[%s] %s\n", prefix, str)
#define BTRFS_TX_DEBUG(str)	BTRFS_TX_PRINT(KERN_DEBUG, "DEBUG", str)
#define BTRFS_TX_WARN(str) 	BTRFS_TX_PRINT(KERN_WARNING, "WARN", str)
#define BTRFS_TX_INFO(str) 	BTRFS_TX_PRINT(KERN_INFO, "INFO", str)


int btrfs_acid_tx_start(struct file * file);

static inline int btrfs_acid_tx_commit(void) { return -EOPNOTSUPP; }
static inline int btrfs_acid_tx_abort(void) {return -EOPNOTSUPP; }

#endif /* __BTRFS_TXBTRFS__ */

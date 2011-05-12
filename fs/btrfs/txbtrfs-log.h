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

struct btrfs_acid_log_entry
{
	struct btrfs_key location;
	u64 clock;
	u16 type;
	size_t size;
	void * data;

	struct list_head list;
};

struct btrfs_acid_log_entry_rw
{
	pgoff_t first_page;
	pgoff_t last_page;
};

struct btrfs_acid_log_entry_attr_rw
{
	unsigned long flags;
};

int btrfs_acid_log_read(struct btrfs_acid_snapshot * snap,
		struct btrfs_key * location, pgoff_t first, pgoff_t last);
int btrfs_acid_log_write(struct btrfs_acid_snapshot * snap,
		struct btrfs_key * location, pgoff_t first, pgoff_t last);
int btrfs_acid_log_attr_get(struct inode * inode);

#endif /* __BTRFS_TXBTRFS_LOG__ */

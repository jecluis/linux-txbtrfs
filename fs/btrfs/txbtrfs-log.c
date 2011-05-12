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
#include "ctree.h"
#include "btrfs_inode.h"
#include "txbtrfs.h"
#include "txbtrfs-log.h"

/* Static methods */
static struct btrfs_acid_log_entry_attr_rw *
__log_create_entry_attr_rw(unsigned int flags);
static struct btrfs_acid_log_entry_rw *
__log_create_entry_rw(pgoff_t first, pgoff_t last);
static struct btrfs_acid_log_entry *
__log_create_entry(struct btrfs_acid_snapshot * snap,
		struct btrfs_key * location, size_t size, void * data, u16 type);

/*
 * Adds a 'read' entry to the read-set.
 */
int btrfs_acid_log_read(struct btrfs_acid_snapshot * snap,
		struct btrfs_key * location, pgoff_t first, pgoff_t last)
{
	int ret = 0;
	struct btrfs_acid_log_entry_rw * rw_entry;
	struct btrfs_acid_log_entry * log_entry;

	BTRFS_SUB_DBG(LOG, "READ: inode [%llu %d %llu] "
				"first page = %d, last page = %d\n",
				location->objectid, location->type, location->offset,
				first, last);


	rw_entry = __log_create_entry_rw(first, last);
	if (IS_ERR(rw_entry))
		return PTR_ERR(rw_entry);

	log_entry = __log_create_entry(snap, location,
			sizeof(*rw_entry), rw_entry, BTRFS_ACID_LOG_READ);
	if (IS_ERR(log_entry))
	{
		ret = PTR_ERR(log_entry);
		goto err_destroy_rw_entry;
	}

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
	struct btrfs_acid_log_entry_rw * rw_entry;
	struct btrfs_acid_log_entry * log_entry;

	BTRFS_SUB_DBG(LOG, "WRITE: inode [%llu %d %llu] "
				"first page = %d, last page = %d\n",
				location->objectid, location->type, location->offset,
				first, last);


	rw_entry = __log_create_entry_rw(first, last);
	if (IS_ERR(rw_entry))
		return PTR_ERR(rw_entry);

	log_entry = __log_create_entry(snap, location,
			sizeof(*rw_entry), rw_entry, BTRFS_ACID_LOG_WRITE);
	if (IS_ERR(log_entry)) {
		ret = PTR_ERR(log_entry);
		goto err_destroy_rw_entry;
	}

	list_add(&log_entry->list, &snap->write_log);

	return ret;

err_destroy_rw_entry:
	kfree(rw_entry);
	return ret;
}

/* Adds an entry to the log referring to a 'get attrs' issued on an inode. */
int btrfs_acid_log_attr_get(struct inode * inode)
{
	struct btrfs_acid_snapshot * snap;
	struct btrfs_inode * our_inode;
	struct btrfs_acid_log_entry_attr_rw * attr_rw_entry;
	struct btrfs_acid_log_entry * log_entry;

	if (unlikely(!inode))
		return -EINVAL;

	our_inode = BTRFS_I(inode);
	snap = our_inode->root->snap;

	if (!snap)
		return -ENOTSUPP;

	attr_rw_entry = __log_create_entry_attr_rw(0);
	if (IS_ERR(attr_rw_entry))
		return PTR_ERR(attr_rw_entry);

	log_entry = __log_create_entry(snap, &our_inode->location,
			sizeof(*attr_rw_entry), attr_rw_entry, BTRFS_ACID_LOG_ATTR_GET);
	if (IS_ERR(log_entry)) {
		kfree(attr_rw_entry);
		return PTR_ERR(log_entry);
	}

	list_add(&log_entry->list, &snap->read_log);

	return 0;
}

static struct btrfs_acid_log_entry_attr_rw *
__log_create_entry_attr_rw(unsigned int flags)
{
	struct btrfs_acid_log_entry_attr_rw * entry;

	entry = kzalloc(sizeof(*entry), GFP_NOFS);
	if (!entry)
		return ERR_PTR(-ENOMEM);

	entry->flags = flags;

	return entry;
}

/*
 * Create a 'Read/Write' entry for the log. Both reads and writes share the
 * same attributes when it comes to logging, so we use the same struct for
 * both of them.
 */
static struct btrfs_acid_log_entry_rw *
__log_create_entry_rw(pgoff_t first, pgoff_t last)
{
	struct btrfs_acid_log_entry_rw * entry;

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
		struct btrfs_key * location, size_t size, void * data, u16 type)
{
	struct btrfs_acid_ctl * ctl;
	struct btrfs_acid_log_entry * entry;
	int clock;

	if (!snap || !location || !data)
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

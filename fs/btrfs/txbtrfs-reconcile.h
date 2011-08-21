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
#ifndef __BTRFS_TXBTRFS_RECONCILE__
#define __BTRFS_TXBTRFS_RECONCILE__

struct btrfs_acid_snapshot;

int btrfs_acid_reconcile(struct btrfs_acid_ctl * ctl,
		struct btrfs_acid_snapshot * txsv, struct btrfs_acid_snapshot * snap);

#endif /* __BTRFS_TXBTRFS_RECONCILE__ */

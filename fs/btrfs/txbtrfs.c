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
#include <linux/fs.h>
#include "txbtrfs.h"

int btrfs_acid_tx_start(struct file * file)
{
//	printk(KERN_DEBUG "[debug] Btrfs ACID Tx Start\n");
//	printk(KERN_WARNING "[warning] Btrfs ACID Tx Start\n");
//	printk(KERN_NOTICE "[notice] Btrfs ACID Tx Start\n");
//	printk(KERN_INFO "[info]ÊBtrfs ACID Tx Start\n");
	BTRFS_TX_DEBUG("ACID Tx Start");

	return 0;
}


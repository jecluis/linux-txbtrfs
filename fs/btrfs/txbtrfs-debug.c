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
#include <linux/kernel.h>
#include <linux/debugfs.h>
#include "txbtrfs-debug.h"
#include "txbtrfs-ctl.h"

#define TXBTRFS_DEBUG_DIR		"txbtrfs"
#define TXBTRFS_DEBUG_COMMIT	"commit"

static const struct seq_operations txbtrfs_debug_seq_ops;
static const struct file_operations txbtrfs_debug_fops;

static struct dentry * txbtrfs_debug_dir = NULL;
static struct dentry * txbtrfs_debug_file = NULL;

static void * txbtrfs_debug_seq_start(struct seq_file * m, loff_t * pos)
{
	return NULL;
}

static void txbtrfs_debug_seq_stop(struct seq_file * m, void * v)
{
}

static void * txbtrfs_debug_seq_next(struct seq_file * m,
		void * v, loff_t * pos)
{
	return NULL;
}

static int txbtrfs_debug_seq_show(struct seq_file * m, void * v)
{
	return 0;
}


static int txbtrfs_debug_fops_open(struct inode * inode, struct file * file)
{
	return seq_open(file, &txbtrfs_debug_seq_ops);
}

int txbtrfs_debug_init(void)
{
	char * f;
	f = TXBTRFS_DEBUG_DIR;
	txbtrfs_debug_dir = debugfs_create_dir(f, NULL);
	if (!txbtrfs_debug_dir)
		goto err;
//	if (!txbtrfs_debug_dir) {
//		printk(KERN_DEBUG "<DEBUG> Unable to create debugfs dir '%s'\n",
//				TXBTRFS_DEBUG_DIR);
//		return -1;
//	}

	f = TXBTRFS_DEBUG_COMMIT;
	txbtrfs_debug_file = debugfs_create_file(f, S_IRUSR,
			txbtrfs_debug_dir, &txbtrfs_debug_fops);
	if (!txbtrfs_debug_file)
		goto err_remove;
//	if (!txbtrfs_debug_file) {
//		printk(KERN_DEBUG "<DEBUG> Unable to create debugfs file '%s'\n",
//				TXBTRFS_DEBUG_COMMIT);
//		return -1;
//	}

	printk(KERN_INFO "<DEBUG> Debug initialized\n");
	return 0;
err_remove:
	txbtrfs_debug_exit();
err:
	printk(KERN_DEBUG "<DEBUG> Unable to create in debugfs '%s'\n", f);
	return -1;
}

void txbtrfs_debug_exit(void)
{
	if (txbtrfs_debug_dir)
		debugfs_remove_recursive(txbtrfs_debug_dir);
	printk(KERN_INFO "<DEBUG> Debug exited/deinitialized\n");
}

static const struct seq_operations txbtrfs_debug_seq_ops = {
		.start	= txbtrfs_debug_seq_start,
		.next 	= txbtrfs_debug_seq_next,
		.stop	= txbtrfs_debug_seq_stop,
		.show	= txbtrfs_debug_seq_show,
};

static const struct file_operations txbtrfs_debug_fops = {
		.open 		= txbtrfs_debug_fops_open,
		.read 		= seq_read,
		.llseek 	= seq_lseek,
		.release 	= seq_release,
		.owner		= THIS_MODULE,
};

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
#include "txbtrfs-ctl.h"
#include "ctree.h"

#if 0

struct btrfs_key;
struct btrfs_root;
struct btrfs_fs_info;
struct btrfs_trans_handle;

#endif /* if 0 */

/* txbtrfs specific structs */
struct btrfs_acid_snapshot_pid
{
	struct list_head list;
	pid_t pid;
};

struct btrfs_acid_snapshot
{
	struct btrfs_root * root;
	struct btrfs_key location;
	struct btrfs_key src_location;
	struct qstr path;
	unsigned long long hash;
	u64 gen;
	pid_t owner_pid;

	atomic_t usage_count;

	struct rw_semaphore known_pids_sem;
	struct list_head known_pids;

	u64 parent_ino;
	u64 dir_index;

	int dead:1;
	int committed:1;

	// read-set
	struct list_head read_log;
	// write-set
	struct list_head write_log;
};

#if 0
///* Debug macros */
#define __TXBTRFS_DEBUG__

#ifdef __TXBTRFS_DEBUG__
#define __TXBTRFS_DEBUG_TX__
#define __TXBTRFS_DEBUG_CALL__
//#define __TXBTRFS_DEBUG_FS__
#define __TXBTRFS_DEBUG_LOG__
#define __TXBTRFS_DEBUG_ACCESS__
#define __TXBTRFS_DEBUG_TX_COMMIT__
#define __TXBTRFS_DEBUG_TX_START__
#endif /* __TXBTRFS_DEBUG__ */

#ifdef __TXBTRFS_DEBUG_TX__
#define BTRFS_TX_PRINT(type, prefix, fmt, args...) \
	printk(type "[" prefix "] " fmt, ## args)

#define BTRFS_TX_DEBUG(fmt, args...) \
	BTRFS_TX_PRINT(KERN_DEBUG, "DEBUG", fmt, ## args)

#define BTRFS_TX_WARN(fmt, args...)  \
	BTRFS_TX_PRINT(KERN_WARNING, "WARN", fmt, ## args)

#define BTRFS_TX_INFO(fmt, args...)  \
	BTRFS_TX_PRINT(KERN_INFO, "INFO", fmt, ## args)

#define BTRFS_TX_DBG(prefix, fmt, args...) \
	printk(KERN_DEBUG "<TX> (%s): " fmt, prefix, ## args)

#else
#define BTRFS_TX_PRINT(type, prefix, fmt, args...) do {} while (0)
#define BTRFS_TX_DEBUG(fmt, args...) do {} while (0)
#define BTRFS_TX_WARN(fmt, args...) do {} while (0)
#define BTRFS_TX_INFO(fmt, args...) do {} while (0)
#define BTRFS_TX_DBG(prefix, fmt, args...) do {} while (0)
#endif /* __TXBTRFS_DEBUG_TX__ */

#ifdef __TXBTRFS_DEBUG_CALL__
#define BTRFS_CALL_DBG(prefix, fmt, args...) \
	printk(KERN_DEBUG "<CALL> (%s): " fmt, prefix, ## args)
#else
#define BTRFS_CALL_DBG(prefix, fmt, args...) do {} while (0)
#endif /* __TXBTRFS_DEBUG_CALL__ */

#ifdef __TXBTRFS_DEBUG_FS__
#define BTRFS_FS_DBG(prefix, fmt, args...) \
	printk(KERN_DEBUG "<FS> (%s): " fmt, prefix, ## args)
#else
#define BTRFS_FS_DBG(prefix, fmt, args...) do {} while (0)
#endif /* __TXBTRFS_DEBUG_FS__ */

#ifdef __TXBTRFS_DEBUG_LOG__
#define BTRFS_LOG_DBG(prefix, fmt, args...) \
	printk(KERN_DEBUG "<LOG> (%s): " fmt, prefix, ## args)
#else
#define BTRFS_LOG_DBG(prefix, fmt, args...) do {} while (0)
#endif /* __TXBTRFS_DEBUG_LOG__ */

#ifdef __TXBTRFS_DEBUG_ACCESS__
#define BTRFS_ACCESS_DBG(prefix, fmt, args...) \
	printk(KERN_DEBUG "<ACCESS> (%s): " fmt, prefix, ## args)
#else
#define BTRFS_ACCESS_DBG(prefix, fmt, args...) do {} while (0)
#endif /* __TXBTRFS_DEBUG_ACCESS__ */

#ifdef __TXBTRFS_DEBUG_TX_COMMIT__
#define BTRFS_TX_COMMIT_DBG(prefix, fmt, args...) \
	printk(KERN_DEBUG "<TX-COMMIT> (%s): " fmt, prefix, ## args)
#else
#define BTRFS_TX_COMMIT_DBG(prefix, fmt, args...) do {} while (0)
#endif /* __TXBTRFS_DEBUG_TX_COMMIT__ */

#ifdef __TXBTRFS_DEBUG_TX_START__
#define BTRFS_TX_START_DBG(prefix, fmt, args...) \
	printk(KERN_DEBUG "<TX-START> (%s): " fmt, prefix, ## args)
#else
#define BTRFS_TX_START_DBG(prefix, fmt, args...) do {} while (0)
#endif /* __TXBTRFS_DEBUG_TX_START__ */

#ifdef __TXBTRFS_DEBUG__
#define BTRFS_SUB_DBG(sub, fmt, args...) \
	BTRFS_##sub##_DBG(__FUNCTION__, fmt, ## args)
#else
#define BTRFS_SUB_DBG(sub, fmt, args...) do {} while (0)
#endif /* __TXBTRFS_DEBUG__ */

#endif /* if 0 */


/* external methods */
//struct btrfs_key * btrfs_acid_copy_key(struct btrfs_key * src);
int btrfs_acid_copy_key(struct btrfs_key * dst, struct btrfs_key * src);

//int btrfs_acid_init(struct btrfs_fs_info * fs_info);

int btrfs_acid_tx_start(struct file * file);
int btrfs_acid_tx_commit(struct file * file);
int btrfs_acid_change_root(struct file * file,
		struct btrfs_ioctl_acid_change_root_args * args);
struct btrfs_acid_snapshot *
btrfs_acid_create_snapshot(struct dentry * txsv_dentry);
int btrfs_acid_destroy_snapshot(struct btrfs_acid_snapshot * snap,
		struct btrfs_fs_info * fs_info);
int btrfs_acid_destroy_txsv(struct btrfs_acid_snapshot * snap,
		struct btrfs_fs_info * fs_info);
int btrfs_acid_create_snapshot_by_ioctl(struct file * file,
		struct btrfs_ioctl_acid_create_snapshot_args * args);
int btrfs_insert_snapshot_item(struct btrfs_trans_handle * trans,
		struct btrfs_root * tree_root, struct btrfs_key * src_key,
		struct btrfs_key * snap_key,
		u64 dir, struct dentry * dentry, u64 dir_index);
int btrfs_delete_snapshot_item(struct btrfs_trans_handle * trans,
		struct btrfs_root * root, struct btrfs_key * location);
int btrfs_insert_tx_subvol_item(struct btrfs_trans_handle * trans,
		struct btrfs_root * tree_root, struct btrfs_key * subvol_key,
		struct qstr * subvol_name, unsigned long parent_ino, u64 superseeder);
int btrfs_delete_tx_subvol_item(struct btrfs_trans_handle * trans,
		struct btrfs_root * root, struct btrfs_key * location);
int btrfs_acid_file_open(struct inode * inode, struct file * file);
void btrfs_acid_vm_open(struct vm_area_struct * area);
int btrfs_acid_set_tx_subvol(struct file * file,
		struct btrfs_ioctl_acid_subvol_flags_args * args);
int btrfs_acid_d_hash(struct dentry * dentry, struct qstr * str);
int btrfs_acid_d_revalidate(struct dentry * dentry, struct nameidata * nd);
int btrfs_is_acid_subvol(struct btrfs_root * root);
int btrfs_is_acid_inode(struct inode * inode);
struct btrfs_acid_snapshot *
btrfs_acid_find_valid_ancestor(struct btrfs_acid_ctl * ctl,
		struct task_struct * task, pid_t * found_pid);
int btrfs_acid_commit_snapshot(struct btrfs_acid_snapshot * snap,
		struct inode * parent_inode, struct inode * snap_inode);

/* inline methods */
//static inline int btrfs_acid_tx_commit(void) { return -EOPNOTSUPP; }
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

/**
 * __is_null_key - returns true iif 'key' is NULL or is filled with zeros.
 */
static inline int __is_null_key(struct btrfs_key * key)
{
	return (!key || (!key->objectid && !key->type && !key->offset));
}

/*
extern const struct inode_operations btrfs_acid_dir_inode_operations;
extern const struct inode_operations btrfs_acid_dir_ro_inode_operations;
extern const struct file_operations btrfs_acid_dir_file_operations;
extern const struct address_space_operations btrfs_acid_aops;
extern const struct address_space_operations btrfs_acid_symlink_aops;
extern const struct inode_operations btrfs_acid_file_inode_operations;
extern const struct inode_operations btrfs_acid_special_inode_operations;
extern const struct inode_operations btrfs_acid_symlink_inode_operations;
extern const struct dentry_operations btrfs_acid_dentry_operations;
extern const struct file_operations btrfs_acid_file_operations;
extern const struct vm_operations_struct btrfs_acid_file_vm_ops;
*/
#endif /* __BTRFS_TXBTRFS__ */

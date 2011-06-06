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
#ifndef __BTRFS_TXBTRFS_CTL__
#define __BTRFS_TXBTRFS_CTL__

struct btrfs_fs_info;

/* struct btrfs_acid_ctl - Allows finer control over the ACID component.
 *
 * To be kept as a field in 'struct btrfs_fs_info', as a control point for
 * all things related to txbtrfs.
 */
struct btrfs_acid_ctl
{
	struct rw_semaphore sv_sem;
	struct btrfs_acid_snapshot * sv;

	struct rw_semaphore curr_snaps_sem;
	struct radix_tree_root current_snapshots;

	atomic_t clock;
};


/* Debug macros */
//#define __TXBTRFS_DEBUG__

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



int btrfs_acid_init(struct btrfs_fs_info * fs_info);


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

#endif /* __BTRFS_TXBTRFS_CTL__ */

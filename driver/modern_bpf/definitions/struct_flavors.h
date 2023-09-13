/* We need this header to keep track of all struct/field/enum changes between kernel versions */

#ifndef __STRUCT_FLAVORS_H__
#define __STRUCT_FLAVORS_H__

#include "vmlinux.h"

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)
#endif

struct mm_struct___v6_2
{
	struct percpu_counter rss_stat[NR_MM_COUNTERS];
};

typedef struct
{
	u64 val;
} kernel_cap_t___v6_3;

/* COS kernels handle audit field differently, see [1]. To support both
 * versions define COS subset of task_struct with a flavor suffix (which will
 * be ignored during relocation matching [2]).
 *
 * [1]: https://chromium.googlesource.com/chromiumos/third_party/kernel/+/096925a44076ba5c52faa84d255a847130ff341e%5E%21/#F2
 * [2]: https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git/tree/tools/lib/bpf/libbpf.c#n5347
 */
struct audit_task_info {
	kuid_t			loginuid;
	unsigned int		sessionid;
	struct audit_context	*ctx;
};

struct task_struct___cos {
	struct audit_task_info		*audit;
};

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif

/* We don't need relocation on these structs, they are internally defined by us as a fallback!
 * Use the prefix `modern_bpf__` before the real name of the struct we want to replace.
 */

/* We use this as a fallback for kernels where `struct __kernel_timespec` is not defined. */
struct modern_bpf__kernel_timespec
{
	long int tv_sec;
	long int tv_nsec;
};

/* We use this as a fallback for kernels where `struct __kernel_timex_timeval` is not defined. */
struct modern_bpf__kernel_timex_timeval
{
	long long int tv_sec;
	long long int tv_usec;
};

struct inode___v6_6 {
	umode_t i_mode;
	short unsigned int i_opflags;
	kuid_t i_uid;
	kgid_t i_gid;
	unsigned int i_flags;
	struct posix_acl *i_acl;
	struct posix_acl *i_default_acl;
	const struct inode_operations *i_op;
	struct super_block *i_sb;
	struct address_space *i_mapping;
	void *i_security;
	long unsigned int i_ino;
	union {
		const unsigned int i_nlink;
		unsigned int __i_nlink;
	};
	dev_t i_rdev;
	loff_t i_size;
	struct timespec64 i_atime;
	struct timespec64 i_mtime;
	struct timespec64 __i_ctime;
	spinlock_t i_lock;
	short unsigned int i_bytes;
	u8 i_blkbits;
	u8 i_write_hint;
	blkcnt_t i_blocks;
	long unsigned int i_state;
	struct rw_semaphore i_rwsem;
	long unsigned int dirtied_when;
	long unsigned int dirtied_time_when;
	struct hlist_node i_hash;
	struct list_head i_io_list;
	struct bdi_writeback *i_wb;
	int i_wb_frn_winner;
	u16 i_wb_frn_avg_time;
	u16 i_wb_frn_history;
	struct list_head i_lru;
	struct list_head i_sb_list;
	struct list_head i_wb_list;
	union {
		struct hlist_head i_dentry;
		struct callback_head i_rcu;
	};
	atomic64_t i_version;
	atomic64_t i_sequence;
	atomic_t i_count;
	atomic_t i_dio_count;
	atomic_t i_writecount;
	atomic_t i_readcount;
	union {
		const struct file_operations *i_fop;
		void (*free_inode)(struct inode *);
	};
	struct file_lock_context *i_flctx;
	struct address_space i_data;
	struct list_head i_devices;
	union {
		struct pipe_inode_info *i_pipe;
		struct cdev *i_cdev;
		char *i_link;
		unsigned int i_dir_seq;
	};
	__u32 i_generation;
	__u32 i_fsnotify_mask;
	struct fsnotify_mark_connector *i_fsnotify_marks;
	struct fscrypt_info *i_crypt_info;
	struct fsverity_info *i_verity_info;
	void *i_private;
};

#endif /* __STRUCT_FLAVORS_H__ */

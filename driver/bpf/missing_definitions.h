/*

Copyright (C) 2023 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/
#ifndef __BPF_MISSING_DEFINITIONS_H__
#define __BPF_MISSING_DEFINITIONS_H__

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 16, 0)
struct ovl_entry {
	union {
		struct {
			unsigned long has_upper;
			bool opaque;
		};
		struct rcu_head rcu;
	};
	unsigned numlower;
	struct path lowerstack[];
};
#else
struct ovl_entry {
	union {
		struct {
			unsigned long flags;
		};
		struct rcu_head rcu;
	};
	unsigned numlower;
	//struct ovl_path lowerstack[];
};

enum ovl_entry_flag {
	OVL_E_UPPER_ALIAS,
	OVL_E_OPAQUE,
	OVL_E_CONNECTED,
};
#endif

#include <linux/mount.h>
/* This require the inlclude `linux/mount.h` for `vfsmount` definition */
struct mount {
    struct hlist_node mnt_hash;
    struct mount *mnt_parent;
    struct dentry *mnt_mountpoint;
    struct vfsmount mnt;
    // ...
};

#endif /*__BPF_MISSING_DEFINITIONS_H__*/

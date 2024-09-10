// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*

Copyright (C) 2023 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/
#ifndef __BPF_MISSING_DEFINITIONS_H__
#define __BPF_MISSING_DEFINITIONS_H__

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

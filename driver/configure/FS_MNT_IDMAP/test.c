/*

Copyright (C) 2025 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/

/*
 * Check that fs function wants mnt_idmap
 * See linux 6.3 changes:
 * - https://github.com/torvalds/linux/commit/abf08576afe3
 * - https://github.com/torvalds/linux/commit/01beba7957a2
 */

#include <linux/module.h>
#include <linux/fs.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("the Falco authors");

static int fs_mnt_idmap_init(void) {
	struct mnt_idmap *idmap = NULL;
	const struct inode *inode = NULL;
	inode_owner_or_capable(idmap, inode);
	return 0;
}

static void fs_mnt_idmap_exit(void) {}

module_init(fs_mnt_idmap_init);
module_exit(fs_mnt_idmap_exit);

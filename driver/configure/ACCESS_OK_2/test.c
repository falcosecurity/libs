/*

Copyright (C) 2023 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/

/*
 * Check that access_ok builds with 2 parameters
 * See https://github.com/torvalds/linux/commit/96d4f267e
 */

#include <linux/module.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("the Falco authors");

static int access_ok_init(void)
{
	access_ok(0, 0);
	return 0;
}

static void access_ok_exit(void)
{
}

module_init(access_ok_init);
module_exit(access_ok_exit);

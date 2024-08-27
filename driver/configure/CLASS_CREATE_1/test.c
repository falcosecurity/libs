/*

Copyright (C) 2024 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/

/*
 * Check that `class_create` builds with only a single parameter
 * See https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=1aaba11da9aa7d7d6b52a74d45b31cac118295a1
 */

#include <linux/module.h>
#include <linux/device.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("the Falco authors");

static int class_create_test_init(void)
{
	struct class *g_ppm_class = class_create("test");
	return 0;
}

static void class_create_test_exit(void)
{
}

module_init(class_create_test_init);
module_exit(class_create_test_exit);

/*

Copyright (C) 2023 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/

/*
 * Check that the build environment is sane
 */

#include <linux/module.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("the Falco authors");

static int empty_init(void) {
	return 0;
}

static void empty_exit(void) {}

module_init(empty_init);
module_exit(empty_exit);

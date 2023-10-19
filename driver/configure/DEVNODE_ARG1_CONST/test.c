/*

Copyright (C) 2023 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/

/*
 * Check for devnode() in struct class taking a const first argument
 * See https://github.com/torvalds/linux/commit/ff62b8e6588fb07bedda7423622c140c4edd66a7
 */

#include <linux/module.h>
#include <linux/device.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("the Falco authors");

static char *ppm_devnode(const struct device *dev, umode_t *mode)
{
	return NULL;
}

static int devnode_dev_const_init(void)
{
	struct class g_ppm_class = {
		.devnode = ppm_devnode
	};
	/* suppress unused variable warning by casting to void */
	(void)g_ppm_class;
	return 0;
}

static void devnode_dev_const_exit(void)
{
}

module_init(devnode_dev_const_init);
module_exit(devnode_dev_const_exit);

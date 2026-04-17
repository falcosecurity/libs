/*

Copyright (C) 2026 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/

#include <linux/module.h>
#include <linux/sched.h>
#include <linux/thread_info.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("the Falco authors");

static int compat_s390_init(void) {
#ifdef CONFIG_S390
	unsigned long flags = task_thread_info(current)->flags & _TIF_31BIT;
	(void)flags;
#endif /* CONFIG_S390 */
	return 0;
}

static void compat_s390_exit(void) {}

module_init(compat_s390_init);
module_exit(compat_s390_exit);

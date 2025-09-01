// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*

Copyright (C) 2024 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/

/*
 * Check that the `pids` field is defined in the `task_struct` struct.
 * Since kernel version 4.19.0 the `pids` field is moved in the `signal_struct` struct, but this
 * change has been backported to older kernels.
 * Hence, this test may also fail on backported kernels even if their version is < 4.19.
 * The version guard here is a best-effort approximation.
 */

#include <linux/version.h>

#include "../../quirks.h"
#include "../../ppm_events_public.h"
#include "../../types.h"

BPF_PROBE("signal/", signal_deliver, signal_deliver_args) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0)
	struct task_struct *task = (struct task_struct *)0;
	if(task->pids) {
		return 1;
	}
	return 0;
#else
#error "task->pids not available. This error can be safely ignored for kernel versions >= 4.19"
#endif
}

char __license[] __bpf_section("license") = "Dual MIT/GPL";

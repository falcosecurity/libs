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
 */

#include "../../quirks.h"
#include "../../ppm_events_public.h"
#include "../../types.h"

BPF_PROBE("signal/", signal_deliver, signal_deliver_args) {
	struct task_struct *task = (struct task_struct *)0;
	if(task->pids) {
		return 1;
	}
	return 0;
}

char __license[] __bpf_section("license") = "Dual MIT/GPL";

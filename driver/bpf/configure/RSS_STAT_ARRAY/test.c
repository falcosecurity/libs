// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*

Copyright (C) 2023 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/

/*
 * Check that mm_struct's field `rss_stat` is an array.
 * See 6.2 kernel commit: https://github.com/torvalds/linux/commit/f1a7941243c102a44e8847e3b94ff4ff3ec56f25
 */

#include "../../quirks.h"
#include "../../ppm_events_public.h"
#include "../../types.h"

// struct mm_struct declaration
#include <linux/mm_types.h>

BPF_PROBE("signal/", signal_deliver, signal_deliver_args)
{
	long val;
	struct mm_struct *mm;
	val = mm->rss_stat[0].count;
	return 0;
}

char __license[] __bpf_section("license") = "Dual MIT/GPL";

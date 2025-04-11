// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*

Copyright (C) 2025 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/

/*
 * Check that kernfs_node's field `parent` exists.
 * See 6.15 kernel commit it is named __parent:
 * https://github.com/torvalds/linux/commit/633488947ef66b194377411322dc9e12aab79b65
 */

#include "../../quirks.h"
#include "../../ppm_events_public.h"
#include "../../types.h"

// struct kernfs_node declaration
#include <linux/kernfs.h>

BPF_PROBE("signal/", signal_deliver, signal_deliver_args) {
	struct kernfs_node *parent;
	struct kernfs_node node;

	parent = node.parent;
	return 0;
}

char __license[] __bpf_section("license") = "Dual MIT/GPL";

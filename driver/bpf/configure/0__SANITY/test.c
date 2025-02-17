// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*

Copyright (C) 2024 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/

/*
 * Check that the build system is sane.
 */

#include "../../quirks.h"
#include "../../ppm_events_public.h"
#include "../../types.h"

BPF_PROBE("sanity/", sanity, sanity_args) {
	return 0;
}

char __license[] __bpf_section("license") = "Dual MIT/GPL";

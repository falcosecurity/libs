// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#pragma once

#include <definitions/vmlinux.h>
#include <definitions/struct_flavors.h>
#include <definitions/missing_definitions.h>
#include <driver/capture_macro.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

/*=============================== DEBUG MACRO ===========================*/

/* For more info about this macro look at https://nakryiko.com/posts/bpf-tips-printk/
 * Note: bpf_trace_printk() can accept only up to 3 input arguments
 * (in addition to fmt and fmt_size). This limitation stems from the BPF helpers
 * ability to accept only up to 5 input arguments in total.
 */

/* Up until Linux 5.9, bpf_trace_printk() would take format string and use it as is.
 * Starting from 5.9 bpf_trace_printk() always appends newline at the end.
 */
#undef bpf_printk
#ifdef __MODERN_BPF_DEBUG__
#define bpf_printk(fmt, ...)                                                           \
	({                                                                             \
		static char ____fmt[] = fmt "\0";                                      \
		if(bpf_core_type_exists(struct trace_event_raw_bpf_trace_printk))      \
		{                                                                      \
			bpf_trace_printk(____fmt, sizeof(____fmt) - 1, ##__VA_ARGS__); \
		}                                                                      \
		else                                                                   \
		{                                                                      \
			____fmt[sizeof(____fmt) - 2] = '\n';                           \
			bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);     \
		}                                                                      \
	})
#else
#define bpf_printk(fmt, ...)
#endif

/*=============================== DEBUG MACRO ===========================*/

// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

/* We need this header to keep track of all struct/field/enum changes between kernel versions */

#ifndef __STRUCT_FLAVORS_H__
#define __STRUCT_FLAVORS_H__

#include "vmlinux.h"

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)
#endif

struct mm_struct___v6_2
{
	struct percpu_counter rss_stat[NR_MM_COUNTERS];
};

typedef struct
{
	uint64_t val;
} kernel_cap_t___v6_3;

/* COS kernels handle audit field differently, see [1]. To support both
 * versions define COS subset of task_struct with a flavor suffix (which will
 * be ignored during relocation matching [2]).
 *
 * [1]: https://chromium.googlesource.com/chromiumos/third_party/kernel/+/096925a44076ba5c52faa84d255a847130ff341e%5E%21/#F2
 * [2]: https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git/tree/tools/lib/bpf/libbpf.c#n5347
 */
struct audit_task_info {
	kuid_t			loginuid;
	unsigned int		sessionid;
	struct audit_context	*ctx;
};

struct task_struct___cos {
	struct audit_task_info		*audit;
};

struct inode___v6_6 {
	struct timespec64 __i_ctime;
};

struct inode___v6_7 {
	struct timespec64 __i_mtime;
};

struct ovl_entry___before_v6_5
{
	long unsigned int flags;
};

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif

/* We don't need relocation on these structs, they are internally defined by us as a fallback!
 * Use the prefix `modern_bpf__` before the real name of the struct we want to replace.
 */

/* We use this as a fallback for kernels where `struct __kernel_timespec` is not defined. */
struct modern_bpf__kernel_timespec
{
	long int tv_sec;
	long int tv_nsec;
};

/* We use this as a fallback for kernels where `struct __kernel_timex_timeval` is not defined. */
struct modern_bpf__kernel_timex_timeval
{
	long long int tv_sec;
	long long int tv_usec;
};

/*
 *  This is equivalent to old_timespec32 or compat_timespec. Some old distros
 *  don't define old_timespec32 (e.g. centos 8 with 4.18 kernel), so we define
 *  it here.
 */
struct modern_bpf__kernel_timespec_ia32
{
	int tv_sec;
	int tv_nsec;
};

#endif /* __STRUCT_FLAVORS_H__ */

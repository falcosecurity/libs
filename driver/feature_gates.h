// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*

Copyright (C) 2023 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/

#ifndef FEATURE_GATES_H
#define FEATURE_GATES_H

/* FEATURE GATES:
 *
 * These feature gates are used by:
 * - kernel module
 * - userspace
 * - modern eBPF probe
 * to compile out some features. The userspace is in charge of
 * filling the eBPF maps that's why it also needs these macros.
 *
 * This file is included by the 2 drivers and the userspace so
 * it could be the right place to define these feature gates.
 */

#ifdef __KERNEL__ /* Kernel module */

#include "ppm_version.h"

///////////////////////////////
// CAPTURE_SCHED_PROC_FORK
///////////////////////////////

/* In some architectures we are not able to catch the `clone exit child
 * event` from the `sys_exit` tracepoint. This is because there is no
 * default behavior among different architectures... you can find more
 * info here:
 * https://www.spinics.net/lists/linux-trace/msg01001.html
 *
 * Anyway, to not lose this event, we need to instrument a new kernel tracepoint:
 *
 * - `sched_process_fork`: allows us to catch every new process that is spawned.
 *
 * In this way we can detect when a child is spawned and we can send to userspace
 * a `PPME_SYSCALL_CLONE_X` event as we do with the `sys_exit` tracepoint.
 *
 * If you run old kernels, you can use the kernel module which requires
 * kernel versions greater or equal than `3.10`, since this tracepoint has
 * been introduced in the following kernel release:
 * https://github.com/torvalds/linux/commit/0a16b6075843325dc402edf80c1662838b929aff
 */
#if defined(CONFIG_ARM64) || defined(CONFIG_S390) || defined(CONFIG_RISCV) || \
        defined(CONFIG_LOONGARCH)
#define CAPTURE_SCHED_PROC_FORK
#endif

///////////////////////////////
// CAPTURE_64BIT_ARGS_SINGLE_REGISTER
///////////////////////////////

/* This is described in syscall(2). Some syscalls take 64-bit arguments. On
 * arches that have 64-bit registers, these arguments are shipped in a register.
 * On 32-bit arches, however, these are split between two consecutive registers,
 * with some alignment requirements. Some require an odd/even pair while some
 * others require even/odd. For now, I assume they all do what x86_32 does, and
 * we can handle the rest when we port those.
 */
#ifdef CONFIG_64BIT
#define CAPTURE_64BIT_ARGS_SINGLE_REGISTER
#endif /* CONFIG_64BIT */

///////////////////////////////
// CAPTURE_CONTEXT_SWITCHES
///////////////////////////////

#define CAPTURE_CONTEXT_SWITCHES

///////////////////////////////
// CAPTURE_SIGNAL_DELIVERIES
///////////////////////////////

#define CAPTURE_SIGNAL_DELIVERIES

///////////////////////////////
// CAPTURE_PAGE_FAULTS
///////////////////////////////

#if(LINUX_VERSION_CODE > KERNEL_VERSION(3, 12, 0)) && defined(CONFIG_X86)
#define CAPTURE_PAGE_FAULTS
#endif

#elif defined(__USE_VMLINUX__) /* modern eBPF probe */

///////////////////////////////
// CAPTURE_SCHED_PROC_FORK
///////////////////////////////

#if defined(__TARGET_ARCH_arm64) || defined(__TARGET_ARCH_s390) || defined(__TARGET_ARCH_riscv) || \
        defined(__TARGET_ARCH_loongarch64)
#define CAPTURE_SCHED_PROC_FORK
#endif

///////////////////////////////
// CAPTURE_PAGE_FAULTS
///////////////////////////////

#if defined(__TARGET_ARCH_x86)
#define CAPTURE_PAGE_FAULTS
#endif

#else /* Userspace */

/* Please note: the userspace loads the filler table for the bpf probe
 * so it must define these macro according to what eBPF supports
 */

///////////////////////////////
// CAPTURE_64BIT_ARGS_SINGLE_REGISTER
///////////////////////////////

#if defined(__x86_64__) || defined(__aarch64__) || defined(__loongarch64)
#define CAPTURE_64BIT_ARGS_SINGLE_REGISTER
#endif

///////////////////////////////
// CAPTURE_CONTEXT_SWITCHES
///////////////////////////////

#define CAPTURE_CONTEXT_SWITCHES

///////////////////////////////
// CAPTURE_SIGNAL_DELIVERIES
///////////////////////////////

#define CAPTURE_SIGNAL_DELIVERIES

///////////////////////////////
// CAPTURE_PAGE_FAULTS
///////////////////////////////

#ifdef __x86_64__
#define CAPTURE_PAGE_FAULTS
#endif /* __x86_64__ */

///////////////////////////////
// CAPTURE_SCHED_PROC_FORK
///////////////////////////////

#if defined(__aarch64__) || defined(__s390x__) || defined(__riscv) || defined(__loongarch64)
#define CAPTURE_SCHED_PROC_FORK
#endif

#endif /* __KERNEL__ */

#endif /* FEATURE_GATES_H */

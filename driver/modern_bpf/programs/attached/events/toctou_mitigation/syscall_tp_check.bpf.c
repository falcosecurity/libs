// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2026 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/base/maps_getters.h>

/* libpman attaches this program once, right after the probe is loaded, and makes one `faccessat`
 * call on each CPU that it can use. If the program counts fewer calls than libpman made, BPF
 * programs on syscall tracepoints that read user memory do not run on every CPU, and libpman
 * opens the perf events that make the TOCTOU mitigation programs run there. See the README.md in
 * this folder.
 *
 * `faccessat` reads its path from user memory in the syscall tracepoint, as the `open` family does.
 *
 * The program counts only the calls whose `mode` is `syscall_tp_check__mode`. libpman sets it to a
 * value that no other caller passes, because the kernel rejects it with EINVAL. libpman picks a
 * new random value for each check, so two checks at the same time do not count the calls of each
 * other. The calls of other processes must not count: they can run the program on a CPU where the
 * calls of libpman do not.
 * A filter on the TGID of libpman would fail in a child PID namespace, where `getpid()` does not
 * return the TGID that `bpf_get_current_pid_tgid()` reports.
 */

// This struct is defined according to the following format file:
// /sys/kernel/tracing/events/syscalls/sys_enter_faccessat/format
struct sys_enter_faccessat_args {
	uint64_t pad1;

	uint32_t __syscall_nr;
	uint32_t pad2;
	uint64_t dfd;
	uint64_t filename;
	uint64_t mode;
};

SEC("tracepoint/syscalls/sys_enter_faccessat")
int syscall_tp_check(struct sys_enter_faccessat_args *ctx) {
	// `mode` is an `int`: the upper 32 bits of the register are not defined.
	if((uint32_t)ctx->mode == syscall_tp_check__mode) {
		syscall_tp_check__hits++;
	}
	return 0;
}

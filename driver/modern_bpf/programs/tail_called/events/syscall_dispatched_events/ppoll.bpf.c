// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/variable_size_event.h>

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(ppoll_x, struct pt_regs *regs, long ret) {
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap) {
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SYSCALL_PPOLL_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	auxmap__store_s64_param(auxmap, ret);

	/* Get the `fds_pointer` and the number of `fds` from the syscall arguments */
	unsigned long fds_pointer = extract__syscall_argument(regs, 0);
	uint32_t nfds = (uint32_t)extract__syscall_argument(regs, 1);

	/* Parameter 2: fds (type: PT_FDLIST) */
	auxmap__store_fdlist_param(auxmap, fds_pointer, nfds, RETURNED_EVENTS);

	/* Parameter 3: timeout (type: PT_RELTIME) */
	uint64_t nanosec = 0;
	unsigned long ts_pointer = extract__syscall_argument(regs, 2);
	if(!bpf_in_ia32_syscall()) {
		if(bpf_core_type_exists(struct __kernel_timespec)) {
			struct __kernel_timespec ts = {0};
			bpf_probe_read_user(&ts,
			                    bpf_core_type_size(struct __kernel_timespec),
			                    (void *)ts_pointer);
			nanosec = ((uint64_t)ts.tv_sec) * SECOND_TO_NS + ts.tv_nsec;
		} else {
			struct modern_bpf__kernel_timespec ts = {0};
			bpf_probe_read_user(&ts, sizeof(ts), (void *)ts_pointer);
			nanosec = ((uint64_t)ts.tv_sec) * SECOND_TO_NS + ts.tv_nsec;
		}
	} else {
		struct modern_bpf__kernel_timespec_ia32 ts = {0};
		bpf_probe_read_user(&ts, sizeof(ts), (void *)ts_pointer);
		nanosec = ((uint32_t)ts.tv_sec) * SECOND_TO_NS + ts.tv_nsec;
	}
	auxmap__store_u64_param(auxmap, nanosec);

	/* Parameter 4: sigmask (type: PT_SIGSET) */
	long unsigned int sigmask[1] = {0};
	unsigned long sigmask_pointer = extract__syscall_argument(regs, 3);
	if(bpf_probe_read_user(&sigmask, sizeof(sigmask), (void *)sigmask_pointer)) {
		/* In case of invalid pointer, return 0 */
		auxmap__store_u32_param(auxmap, (uint32_t)0);
	} else {
		auxmap__store_u32_param(auxmap, (uint32_t)sigmask[0]);
	}

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/

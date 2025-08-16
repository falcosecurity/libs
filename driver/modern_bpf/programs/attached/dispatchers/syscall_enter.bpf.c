// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/syscalls_dispatcher.h>

/* From linux tree: /include/trace/events/syscall.h
 * TP_PROTO(struct pt_regs *regs, long id),
 */
SEC("tp_btf/sys_enter")
int BPF_PROG(sys_enter, struct pt_regs* regs, long syscall_id) {
	int socketcall_syscall_id = -1;

	if(bpf_in_ia32_syscall()) {
#if defined(__TARGET_ARCH_x86)
		if(syscall_id == __NR_ia32_socketcall) {
			socketcall_syscall_id = __NR_ia32_socketcall;
		} else {
			syscall_id = maps__ia32_to_64(syscall_id);
			// syscalls defined only on 32 bits are dropped here.
			if(syscall_id == (uint32_t)-1) {
				return 0;
			}
		}
#else
		return 0;
#endif
	} else {
#ifdef __NR_socketcall
		socketcall_syscall_id = __NR_socketcall;
#endif
	}

	// We convert it here in this way the syscall will be treated exactly as the original one.
	if(syscall_id == socketcall_syscall_id) {
		int socketcall_call = (int)extract__syscall_argument(regs, 0);
		syscall_id = syscalls_dispatcher__convert_socketcall_call_to_syscall_id(socketcall_call);
		if(syscall_id == -1) {
			// We can't do anything since modern bpf filler jump table is syscall indexed
			return 0;
		}
	}

	// The following system calls are already handled by TOCTOU mitigation programs and will not
	// have an entry in the syscall enter tail table, so simply return early, avoiding wasting
	// resources on any additional filtering logic.
	switch(syscall_id) {
#if defined(__NR_openat2)
#ifdef __NR_openat2
	case __NR_openat2:
#endif  // __NR_openat2
		return 0;
#endif  // __NR_openat2
	default:
		break;
	}

	if(!syscalls_dispatcher__64bit_interesting_syscall(syscall_id)) {
		return 0;
	}

	if(syscalls_dispatcher__sampling_logic_enter(syscall_id)) {
		return 0;
	}

	bpf_tail_call(ctx, &syscall_enter_tail_table, syscall_id);
	return 0;
}

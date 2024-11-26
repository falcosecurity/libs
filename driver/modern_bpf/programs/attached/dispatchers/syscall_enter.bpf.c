// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/syscalls_dispatcher.h>

// We don't want to send DROP_E/DROP_X events from the enter tracepoint because it would requires us
// to create a dedicated tail table for the enter. It is enough to send DROP_E/DROP_X events from
// the exit tracepoint.
static __always_inline bool sampling_logic_enter(void* ctx, uint32_t id) {
	/* If dropping mode is not enabled we don't perform any sampling
	 * false: means don't drop the syscall
	 * true: means drop the syscall
	 */
	if(!maps__get_dropping_mode()) {
		return false;
	}

	uint8_t sampling_flag = maps__64bit_sampling_syscall_table(id);

	if(sampling_flag == UF_NEVER_DROP) {
		return false;
	}

	if(sampling_flag == UF_ALWAYS_DROP) {
		return true;
	}

	// If we are in the sampling period we drop the event
	if((bpf_ktime_get_boot_ns() % SECOND_TO_NS) >= (SECOND_TO_NS / maps__get_sampling_ratio())) {
		return true;
	}

	return false;
}

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

	/* we convert it here in this way the syscall will be treated exactly as the original one */
	if(syscall_id == socketcall_syscall_id) {
		syscall_id = convert_network_syscalls(regs);
		if(syscall_id == -1) {
			// We can't do anything since modern bpf filler jump table is syscall indexed
			return 0;
		}
	}

	if(!syscalls_dispatcher__64bit_interesting_syscall(syscall_id)) {
		return 0;
	}

	if(sampling_logic_enter(ctx, syscall_id)) {
		return 0;
	}

	bpf_tail_call(ctx, &syscall_enter_tail_table, syscall_id);
	return 0;
}

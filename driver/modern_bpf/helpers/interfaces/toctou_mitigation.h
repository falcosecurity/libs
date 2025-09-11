// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2025 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#pragma once

#include <helpers/interfaces/syscalls_dispatcher.h>
#include <helpers/interfaces/variable_size_event.h>

static __always_inline bool toctou_mitigation__sampling_logic_enter(uint32_t syscall_id) {
	/* If dropping mode is not enabled we don't perform any sampling. Notice that:
	 * - false: means don't drop the syscall
	 * - true: means drop the syscall
	 */
	if(!maps__get_dropping_mode()) {
		return false;
	}

	uint8_t sampling_flag = maps__64bit_sampling_syscall_table(syscall_id);

	if(sampling_flag == UF_NEVER_DROP) {
		return false;
	}

	if(sampling_flag == UF_ALWAYS_DROP) {
		return true;
	}

	// If we are in the sampling period we drop the event.
	if((bpf_ktime_get_boot_ns() % SECOND_TO_NS) >= (SECOND_TO_NS / maps__get_sampling_ratio())) {
		return true;
	}

	return false;
}

/**
 * @brief Tell if the event related to the specified 64 bit system call should be droppped or not.
 *
 * @param syscall_id is the original system call id that triggered the program
 * @param socketcall_call (socketcall-only) is the call argument provided to the socketcall system
 * call (e.g.: SYS_CONNECT)
 * @return Returns 1 if the event should be dropped, 0 otherwise
 */
static __always_inline int toctou_mitigation__64bit_should_drop(uint32_t syscall_id,
                                                                int socketcall_call) {
#ifdef __NR_socketcall
	uint32_t socketcall_syscall_id = __NR_socketcall;
#else
	uint32_t socketcall_syscall_id = -1;
#endif

	// Convert the socketcall id into the network syscall id.
	// In this way the syscall will be treated exactly as the original one.
	if(syscall_id == socketcall_syscall_id) {
		syscall_id = syscalls_dispatcher__convert_socketcall_call_to_syscall_id(socketcall_call);
		if(syscall_id == -1) {
			// We can't do anything since modern bpf filler jump table is syscall indexed.
			return 1;
		}
	}

	if(!syscalls_dispatcher__64bit_interesting_syscall(syscall_id)) {
		return 1;
	}

	if(toctou_mitigation__sampling_logic_enter(syscall_id)) {
		return 1;
	}

	return 0;
}

/**
 * @brief Tell if the event related to the specified ia-32 system call should be droppped or not.
 *
 * @param syscall_id is the original system call id that triggered the program
 * @param socketcall_call (socketcall-only) is the call argument provided to the socketcall system
 * call (e.g.: SYS_CONNECT)
 * @return Returns 1 if the event should be dropped, 0 otherwise
 */
static __always_inline int toctou_mitigation__ia32_should_drop(uint32_t syscall_id,
                                                               int socketcall_call) {
#ifndef __TARGET_ARCH_x86
	return 1;
#else
	int socketcall_syscall_id = -1;
	if(syscall_id == __NR_ia32_socketcall) {
		socketcall_syscall_id = __NR_ia32_socketcall;
	} else {
		syscall_id = maps__ia32_to_64(syscall_id);
		// Syscalls defined only on 32 bits are dropped here.
		if(syscall_id == (uint32_t)-1) {
			return 1;
		}
	}

	// Convert the socketcall id into the network syscall id.
	// In this way the syscall will be treated exactly as the original one.
	if(syscall_id == socketcall_syscall_id) {
		syscall_id = syscalls_dispatcher__convert_socketcall_call_to_syscall_id(socketcall_call);
		if(syscall_id == -1) {
			// We can't do anything since modern bpf filler jump table is syscall indexed.
			return 1;
		}
	}

	if(!syscalls_dispatcher__64bit_interesting_syscall(syscall_id)) {
		return 1;
	}

	if(toctou_mitigation__sampling_logic_enter(syscall_id)) {
		return 1;
	}

	return 0;
#endif  // __TARGET_ARCH_x86
}

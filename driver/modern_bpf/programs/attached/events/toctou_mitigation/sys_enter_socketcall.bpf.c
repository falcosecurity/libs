// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2025 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/toctou_mitigation.h>

// This struct is defined according to the following format file:
// /sys/kernel/tracing/events/syscalls/sys_enter_socketcall/format
struct sys_enter_socketcall_args {
	uint64_t pad1;

	uint32_t __syscall_nr;
	uint32_t pad2;
	uint64_t call;
	uint64_t args;
};

/*=============================== ENTER DISPATCHER ===========================*/

SEC("tracepoint/syscalls/sys_enter_socketcall")
int socketcall_e(struct sys_enter_socketcall_args *ctx) {
	/* This programs serves only to implement TOCTOU mitigation for 'connect'. */
	if(ctx->call != SYS_CONNECT) {
		return 0;
	}

	return toctou_mitigation__call_prog(ctx, ctx->__syscall_nr, ctx->call, TTM_SOCKETCALL_E);
}

/*=============================== ENTER DISPATCHER ===========================*/

/*=============================== ENTER EVENT ===========================*/

SEC("tracepoint/syscalls/sys_enter_socketcall")
int ttm_socketcall_e(struct sys_enter_socketcall_args *ctx) {
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap) {
		return 0;
	}

	/* Extract syscall arguments from socketcall args pointer. */
	unsigned long args[3] = {0};
	void *args_pointer = (void *)ctx->args;
	if(bpf_in_ia32_syscall()) {
		// First read all arguments on 32 bits.
		uint32_t args_u32[3] = {};
		bpf_probe_read_user(args_u32, 3 * sizeof(uint32_t), args_pointer);
		for(int i = 0; i < 3; i++) {
			args[i] = (unsigned long)args_u32[i];
		}
	} else {
		bpf_probe_read_user(args, 3 * sizeof(unsigned long), args_pointer);
	}

	int64_t socket_fd = (int64_t)(int32_t)args[0];
	unsigned long usrsockaddr = (unsigned long)args[1];
	uint16_t usrsockaddr_len = (uint16_t)args[2];

	toctou_mitigation__push_connect_enter_event(auxmap, socket_fd, usrsockaddr, usrsockaddr_len);
	return 0;
}

/*=============================== ENTER EVENT ===========================*/

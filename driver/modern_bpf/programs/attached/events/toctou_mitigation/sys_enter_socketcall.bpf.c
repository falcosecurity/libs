// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2025 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/toctou_mitigation.h>

/*=============================== ENTER EVENT ===========================*/

// This struct is defined according to the following format file:
// /sys/kernel/tracing/events/syscalls/sys_enter_socketcall/format
struct sys_enter_socketcall_args {
	uint64_t pad1;

	uint32_t __syscall_nr;
	uint32_t pad2;
	uint64_t call;
	uint64_t args;
};

SEC("tracepoint/syscalls/sys_enter_socketcall")
int socketcall_e(struct sys_enter_socketcall_args *ctx) {
	/* This programs serves only to implement TOCTOU mitigation for 'connect'. */
	if(ctx->call != SYS_CONNECT) {
		return 0;
	}

	if(toctou_mitigation__64bit_should_drop(ctx->__syscall_nr, ctx->call)) {
		return 0;
	}

	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap) {
		return 0;
	}

	/* Extract connect syscall arguments from socketcall args pointer. */
	void *args_pointer = (void *)ctx->args;
	unsigned long args[3] = {0};
	bpf_probe_read_user(args, 3 * sizeof(unsigned long), args_pointer);

	int64_t socket_fd = (int64_t)(int32_t)args[0];
	unsigned long usrsockaddr = (unsigned long)args[1];
	uint16_t usrsockaddr_len = (uint16_t)args[2];

	toctou_mitigation__submit_connect_enter_event(auxmap, socket_fd, usrsockaddr, usrsockaddr_len);
	return 0;
}

static __always_inline int ia32_handler(struct pt_regs *regs, long int retval) {
	uint64_t socketcall_call = extract__syscall_argument(regs, 0);
	/* This programs serves only to implement TOCTOU mitigation for 'connect'. */
	if(socketcall_call != SYS_CONNECT) {
		return 0;
	}

	if(toctou_mitigation__ia32_should_drop(__NR_ia32_socketcall, socketcall_call)) {
		return 0;
	}

	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap) {
		return 0;
	}

	/* Extract connect syscall arguments from registers. */
	void *args_pointer = (void *)extract__syscall_argument(regs, 1);
	unsigned long args[3] = {0};
	uint32_t args_u32[3] = {};
	bpf_probe_read_user(args_u32, 3 * sizeof(uint32_t), args_pointer);
	for(int i = 0; i < 3; i++) {
		args[i] = (unsigned long)args_u32[i];
	}

	int64_t socket_fd = (int64_t)(int32_t)args[0];
	unsigned long usrsockaddr = (unsigned long)args[1];
	uint16_t usrsockaddr_len = (uint16_t)args[2];

	toctou_mitigation__submit_connect_enter_event(auxmap, socket_fd, usrsockaddr, usrsockaddr_len);
	return 0;
}

SEC("fentry/__ia32_sys_socketcall")
int BPF_PROG(ia32_socketcall_e, struct pt_regs *regs, long int retval) {
	return ia32_handler(regs, retval);
}

SEC("fentry/__ia32_compat_sys_socketcall")
int BPF_PROG(ia32_compat_socketcall_e, struct pt_regs *regs, long int retval) {
	return ia32_handler(regs, retval);
}

/*=============================== ENTER EVENT ===========================*/

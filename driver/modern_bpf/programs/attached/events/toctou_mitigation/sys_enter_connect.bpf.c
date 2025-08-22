// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2025 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/toctou_mitigation.h>
#include <helpers/interfaces/variable_size_event.h>

static __always_inline void submit_connect_enter_event(struct auxiliary_map* auxmap,
                                                       int64_t socket_fd,
                                                       unsigned long usrsockaddr,
                                                       uint16_t usrsockaddr_len) {
	auxmap__preload_event_header(auxmap, PPME_SOCKET_CONNECT_E);

	/*=============================== STORE PARAMETERS  ===========================*/

	/* Parameter 1: fd (type: PT_FD) */
	auxmap__store_s64_param(auxmap, socket_fd);

	/* Parameter 2: addr (type: PT_SOCKADDR) */
	auxmap__store_sockaddr_param(auxmap, usrsockaddr, usrsockaddr_len);

	/*=============================== STORE PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);
}

/*=========================== COMMON 64BIT SUPPORT (TRACEPOINT-BASED) =======================*/

// This struct is defined according to the following format file:
// /sys/kernel/tracing/events/syscalls/sys_enter_connect/format
struct sys_enter_connect_args {
	uint64_t pad1;

	uint32_t __syscall_nr;
	uint32_t pad2;
	uint64_t fd;
	uint64_t uservaddr;
	uint64_t addrlen;
};

SEC("tracepoint/syscalls/sys_enter_connect")
int connect_e(struct sys_enter_connect_args* ctx) {
	if(toctou_mitigation__64bit_should_drop(ctx->__syscall_nr, -1)) {
		return 0;
	}

	struct auxiliary_map* auxmap = auxmap__get();
	if(!auxmap) {
		return 0;
	}

	/* Extract syscall arguments from context. */
	int64_t socket_fd = (int64_t)(int32_t)ctx->fd;
	unsigned long usrsockaddr = (unsigned long)ctx->uservaddr;
	uint16_t usrsockaddr_len = (uint16_t)ctx->addrlen;

	submit_connect_enter_event(auxmap, socket_fd, usrsockaddr, usrsockaddr_len);
	return 0;
}

/*=========================== COMMON 64BIT SUPPORT (TRACEPOINT-BASED) =======================*/

/*=============================== IA-32 SUPPORT (KPROBE-BASED) ===========================*/

static __always_inline int ia32_common_handler(struct pt_regs* regs) {
	if(toctou_mitigation__ia32_should_drop(__NR_ia32_connect, -1)) {
		return 0;
	}

	struct auxiliary_map* auxmap = auxmap__get();
	if(!auxmap) {
		return 0;
	}

	/* Extract syscall arguments from registers. */
	int64_t socket_fd = (int64_t)(int32_t)extract__syscall_argument(regs, 0);
	unsigned long usrsockaddr = (unsigned long)extract__syscall_argument(regs, 1);
	uint16_t usrsockaddr_len = (uint16_t)extract__syscall_argument(regs, 2);

	submit_connect_enter_event(auxmap, socket_fd, usrsockaddr, usrsockaddr_len);
	return 0;
}

SEC("kprobe/__ia32_compat_sys_connect")
int BPF_KPROBE(ia32_compat_connect_e, struct pt_regs* regs) {
	return ia32_common_handler(regs);
}

SEC("kprobe/__ia32_sys_connect")
int BPF_KPROBE(ia32_connect_e, struct pt_regs* regs) {
	return ia32_common_handler(regs);
}

/*=============================== IA-32 SUPPORT (KPROBE-BASED) ===========================*/

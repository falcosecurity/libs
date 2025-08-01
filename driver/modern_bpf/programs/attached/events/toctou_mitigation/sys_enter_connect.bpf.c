// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2025 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/toctou_mitigation.h>

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

/*=============================== ENTER DISPATCHER ===========================*/

SEC("tracepoint/syscalls/sys_enter_connect")
int connect_e(struct sys_enter_connect_args* ctx) {
	return toctou_mitigation__call_prog(ctx, ctx->__syscall_nr, -1, TTM_CONNECT_E);
}

/*=============================== ENTER DISPATCHER ===========================*/

/*=============================== ENTER EVENT ===========================*/

SEC("tracepoint/syscalls/sys_enter_connect")
int ttm_connect_e(struct sys_enter_connect_args* ctx) {
	struct auxiliary_map* auxmap = auxmap__get();
	if(!auxmap) {
		return 0;
	}

	/* Extract syscall arguments from context. */
	int64_t socket_fd = (int64_t)(int32_t)ctx->fd;
	unsigned long usrsockaddr = (unsigned long)ctx->uservaddr;
	uint16_t usrsockaddr_len = (uint16_t)ctx->addrlen;

	toctou_mitigation__push_connect_enter_event(auxmap, socket_fd, usrsockaddr, usrsockaddr_len);
	return 0;
}

/*=============================== ENTER EVENT ===========================*/

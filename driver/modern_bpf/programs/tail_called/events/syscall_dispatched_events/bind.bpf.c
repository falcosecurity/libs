// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>
#include <helpers/interfaces/variable_size_event.h>

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(bind_x, struct pt_regs *regs, long ret) {
	if(maps__get_dropping_mode() && ret < 0) {
		return 0;
	}

	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap) {
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SOCKET_BIND_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/
	/* Collect parameters at the beginning to easily manage socketcalls */
	unsigned long args[3] = {0};
	extract__network_args(args, 3, regs);

	/* Parameter 1: res (type: PT_ERRNO) */
	auxmap__store_s64_param(auxmap, ret);

	/* Parameter 2: addr (type: PT_SOCKADDR) */
	unsigned long sockaddr_ptr = args[1];
	uint16_t addrlen = (uint16_t)args[2];
	auxmap__store_sockaddr_param(auxmap, sockaddr_ptr, addrlen);

	/* Parameter 3: fd (type: PT_FD) */
	auxmap__store_s64_param(auxmap, (int64_t)(int32_t)args[0]);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/

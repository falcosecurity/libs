// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(shutdown_e, struct pt_regs *regs, long id) {
	/* We need to keep this at the beginning of the program because otherwise we alter the state of
	 * the ebpf registers causing a verifier issue.
	 */
	unsigned long args[2] = {0};
	extract__network_args(args, 2, regs);

	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, SHUTDOWN_E_SIZE, PPME_SOCKET_SHUTDOWN_E)) {
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: fd (type: PT_FD) */
	int64_t fd = (int32_t)args[0];
	ringbuf__store_s64(&ringbuf, fd);

	/* Parameter 2: how (type: PT_ENUMFLAGS8) */
	int how = (int32_t)args[1];
	ringbuf__store_u8(&ringbuf, (uint8_t)shutdown_how_to_scap(how));

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(shutdown_x, struct pt_regs *regs, long ret) {
	/* We need to keep this at the beginning of the program because otherwise we alter the state of
	 * the ebpf registers causing a verifier issue.
	 */
	unsigned long args[2] = {0};
	extract__network_args(args, 2, regs);

	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, SHUTDOWN_X_SIZE, PPME_SOCKET_SHUTDOWN_X)) {
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	ringbuf__store_s64(&ringbuf, ret);

	/* Parameter 2: fd (type: PT_FD) */
	int64_t fd = (int32_t)args[0];
	ringbuf__store_s64(&ringbuf, fd);

	/* Parameter 3: how (type: PT_ENUMFLAGS8) */
	int how = (int32_t)args[1];
	ringbuf__store_u8(&ringbuf, (uint8_t)shutdown_how_to_scap(how));

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/

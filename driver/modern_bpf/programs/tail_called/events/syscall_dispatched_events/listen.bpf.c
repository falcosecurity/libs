// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(listen_x, struct pt_regs *regs, long ret) {
	/* We need to keep this at the beginning of the program because otherwise we alter the state of
	 * the ebpf registers causing a verifier issue.
	 */
	unsigned long args[2] = {0};
	extract__network_args(args, 2, regs);

	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, LISTEN_X_SIZE, PPME_SOCKET_LISTEN_X)) {
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	ringbuf__store_s64(&ringbuf, ret);

	/* Parameter 2: fd (type: PT_FD) */
	int32_t fd = (int32_t)args[0];
	ringbuf__store_s64(&ringbuf, (int64_t)fd);

	/* Parameter 3: backlog (type: PT_INT32) */
	int32_t backlog = (int32_t)args[1];
	ringbuf__store_s32(&ringbuf, backlog);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/

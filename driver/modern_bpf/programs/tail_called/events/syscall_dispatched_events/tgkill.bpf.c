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
int BPF_PROG(tgkill_e, struct pt_regs *regs, long id) {
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, TGKILL_E_SIZE, PPME_SYSCALL_TGKILL_E)) {
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: tgid (type: PT_PID) */
	pid_t tgid = (int32_t)extract__syscall_argument(regs, 0);
	ringbuf__store_s64(&ringbuf, (int64_t)tgid);

	/* Parameter 2: tid (type: PT_PID) */
	pid_t tid = (int32_t)extract__syscall_argument(regs, 1);
	ringbuf__store_s64(&ringbuf, (int64_t)tid);

	/* Parameter 3: sig (type: PT_SIGTYPE) */
	uint8_t sig = (uint8_t)extract__syscall_argument(regs, 2);
	ringbuf__store_u8(&ringbuf, sig);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(tgkill_x, struct pt_regs *regs, long ret) {
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, TGKILL_X_SIZE, PPME_SYSCALL_TGKILL_X)) {
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);
	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	ringbuf__store_s64(&ringbuf, ret);

	/* Parameter 2: pid (type: PT_PID) */
	pid_t pid = (int32_t)extract__syscall_argument(regs, 0);
	ringbuf__store_s64(&ringbuf, (int64_t)pid);

	/* Parameter 3: tid (type: PT_PID) */
	pid_t tid = (int32_t)extract__syscall_argument(regs, 1);
	ringbuf__store_s64(&ringbuf, (int64_t)tid);

	/* Parameter 4: sig (type: PT_SIGTYPE) */
	uint8_t sig = (uint8_t)extract__syscall_argument(regs, 2);
	ringbuf__store_u8(&ringbuf, sig);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/

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
int BPF_PROG(flock_x, struct pt_regs *regs, long ret) {
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, FLOCK_X_SIZE, PPME_SYSCALL_FLOCK_X)) {
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	ringbuf__store_s64(&ringbuf, ret);

	/* Parameter 2: fd (type: PT_FD) */
	int64_t fd = (int64_t)(int32_t)extract__syscall_argument(regs, 0);
	ringbuf__store_s64(&ringbuf, fd);

	/* Parameter 3: operation (type: PT_FLAGS32) */
	unsigned long operation = extract__syscall_argument(regs, 1);
	ringbuf__store_u32(&ringbuf, flock_flags_to_scap((int)operation));

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/

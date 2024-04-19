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
int BPF_PROG(io_uring_enter_e,
	     struct pt_regs *regs,
	     long id)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, IO_URING_ENTER_E_SIZE, PPME_SYSCALL_IO_URING_ENTER_E))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	// Here we have no parameters to collect.

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(io_uring_enter_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, IO_URING_ENTER_X_SIZE, PPME_SYSCALL_IO_URING_ENTER_X))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	ringbuf__store_s64(&ringbuf, ret);

	/* Parameter 2: fd (type: PT_FD) */
	int32_t fd = (int32_t)extract__syscall_argument(regs, 0);
	ringbuf__store_s64(&ringbuf, (int64_t)fd);

	/* Parameter 3: to_submit (type: PT_UINT32) */
	uint32_t to_submit = (uint32_t)extract__syscall_argument(regs, 1);
	ringbuf__store_u32(&ringbuf, to_submit);

	/* Parameter 4: min_complete (type: PT_UINT32) */
	uint32_t min_complete = (uint32_t)extract__syscall_argument(regs, 2);
	ringbuf__store_u32(&ringbuf, min_complete);

	/* Parameter 5: flags (type: PT_FLAGS32) */
	uint32_t flags = (uint32_t)extract__syscall_argument(regs, 3);
	ringbuf__store_u32(&ringbuf, io_uring_enter_flags_to_scap(flags));

	/* Parameter 6: sig (type: PT_SIGSET) */
	/* This is unclear, why we store only the first 32 bit? this is a pointer!
	 * It could be also a pointer to a `struct io_uring_getevents_args`.
	 */
	uint32_t sig = (uint32_t)extract__syscall_argument(regs, 4);
	ringbuf__store_u32(&ringbuf, sig);

	/// TODO: We miss the last parameter `size_t argsz`
	/// we need to implement it in all our drivers

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/

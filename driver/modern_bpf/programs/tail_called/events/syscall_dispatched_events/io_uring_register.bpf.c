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
int BPF_PROG(io_uring_register_e,
	     struct pt_regs *regs,
	     long id)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, IO_URING_REGISTER_E_SIZE, PPME_SYSCALL_IO_URING_REGISTER_E))
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
int BPF_PROG(io_uring_register_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, IO_URING_REGISTER_X_SIZE, PPME_SYSCALL_IO_URING_REGISTER_X))
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

	/* Parameter 3: opcode (type: PT_ENUMFLAGS16) */
	uint32_t opcode = (uint32_t)extract__syscall_argument(regs, 1);
	ringbuf__store_u16(&ringbuf, (uint16_t)io_uring_register_opcodes_to_scap(opcode));

	/* Parameter 4: arg (type: PT_UINT64) */
	/* Here we push directly a pointer to userspace. `arg` is
	 * pointer to `struct io_uring_rsrc_register`
	 */
	unsigned long arg = extract__syscall_argument(regs, 2);
	ringbuf__store_u64(&ringbuf, arg);

	/* Parameter 5: nr_args (type: PT_UINT32) */
	uint32_t nr_args = (uint32_t)extract__syscall_argument(regs, 3);
	ringbuf__store_u32(&ringbuf, nr_args);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/

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
int BPF_PROG(signalfd_e,
	     struct pt_regs *regs,
	     long id)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, SIGNALFD_E_SIZE, PPME_SYSCALL_SIGNALFD_E))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: fd (type: PT_FD) */
	int32_t fd = (int32_t)extract__syscall_argument(regs, 0);
	ringbuf__store_s64(&ringbuf, (int64_t)fd);

	/* Parameter 2: mask (type: PT_UINT32) */
	/* Right now we are not interested in the `sigmask`, we can populate it if we need */
	ringbuf__store_u32(&ringbuf, 0);

	/* Parameter 3: flags (type: PT_UINT8) */
	/* The syscall `signalfd` has no flags! only `signalfd4` has the `flags` param.
	 * For compatibility with the event definition here we send `0` as flags.
	 */
	ringbuf__store_u8(&ringbuf, 0);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(signalfd_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, SIGNALFD_X_SIZE, PPME_SYSCALL_SIGNALFD_X))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_FD)*/
	ringbuf__store_s64(&ringbuf, ret);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/

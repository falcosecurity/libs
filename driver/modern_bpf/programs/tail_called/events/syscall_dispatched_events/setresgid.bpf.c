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
int BPF_PROG(setresgid_e,
	     struct pt_regs *regs,
	     long id)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, SETRESGID_E_SIZE, PPME_SYSCALL_SETRESGID_E))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: rgid (type: PT_GID) */
	gid_t rgid = (uint32_t)extract__syscall_argument(regs, 0);
	ringbuf__store_u32(&ringbuf, rgid);

	/* Parameter 2: egid (type: PT_GID) */
	gid_t egid = (uint32_t)extract__syscall_argument(regs, 1);
	ringbuf__store_u32(&ringbuf, egid);

	/* Parameter 3: sgid (type: PT_GID) */
	gid_t sgid = (uint32_t)extract__syscall_argument(regs, 2);
	ringbuf__store_u32(&ringbuf, sgid);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(setresgid_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, SETRESGID_X_SIZE, PPME_SYSCALL_SETRESGID_X))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO)*/
	ringbuf__store_s64(&ringbuf, ret);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/

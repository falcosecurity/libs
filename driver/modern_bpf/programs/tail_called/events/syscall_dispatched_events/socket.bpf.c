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
int BPF_PROG(socket_e,
	     struct pt_regs *regs,
	     long id)
{
	/* Collect parameters at the beginning so we can easily manage socketcalls */
	unsigned long args[3];
	extract__network_args(args, 3, regs);

	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, SOCKET_E_SIZE, PPME_SOCKET_SOCKET_E))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: domain (type: PT_ENUMFLAGS32) */
	/* why to send 32 bits if we need only 8 bits? */
	uint8_t domain = (uint8_t)args[0];
	ringbuf__store_u32(&ringbuf, (uint32_t)socket_family_to_scap(domain));

	/* Parameter 2: type (type: PT_UINT32) */
	/* this should be an int, not a uint32 */
	uint32_t type = (uint32_t)args[1];
	ringbuf__store_u32(&ringbuf, type);

	/* Parameter 3: proto (type: PT_UINT32) */
	/* this should be an int, not a uint32 */
	uint32_t proto = (uint32_t)args[2];
	ringbuf__store_u32(&ringbuf, proto);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(socket_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, SOCKET_X_SIZE, PPME_SOCKET_SOCKET_X))
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

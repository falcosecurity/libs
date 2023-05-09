/*
 * Copyright (C) 2022 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(generic_e,
	     struct pt_regs *regs,
	     long id)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, GENERIC_E_SIZE, PPME_GENERIC_E))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS ===========================*/

	/* Parameter 1: ID (type: PT_SYSCALLID) */
	/* This is the PPM_SC code obtained from the syscall id. */
	ringbuf__store_u16(&ringbuf, maps__get_ppm_sc(id));

	/* Parameter 2: nativeID (type: PT_UINT16) */
	ringbuf__store_u16(&ringbuf, id);

	/*=============================== COLLECT PARAMETERS ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(generic_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, GENERIC_X_SIZE, PPME_GENERIC_X))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS ===========================*/

	/* Parameter 1: ID (type: PT_SYSCALLID) */
	/* This is the PPM_SC code obtained from the syscall id. */
	ringbuf__store_u16(&ringbuf, maps__get_ppm_sc(extract__syscall_id(regs)));

	/*=============================== COLLECT PARAMETERS ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/

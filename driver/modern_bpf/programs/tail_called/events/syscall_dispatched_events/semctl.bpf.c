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
int BPF_PROG(semctl_e,
	     struct pt_regs *regs,
	     long id)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, SEMCTL_E_SIZE, PPME_SYSCALL_SEMCTL_E))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: semid (type: PT_INT32) */
	int32_t semid = (int32_t)extract__syscall_argument(regs, 0);
	ringbuf__store_s32(&ringbuf, semid);

	/* Parameter 2: semnum (type: PT_INT32) */
	int32_t semnum = (int32_t)extract__syscall_argument(regs, 1);
	ringbuf__store_s32(&ringbuf, semnum);

	/* Parameter 3: cmd (type: PT_FLAGS16) */
	uint16_t cmd = (uint16_t)extract__syscall_argument(regs, 2);
	ringbuf__store_u16(&ringbuf, semctl_cmd_to_scap(cmd));

	/* Parameter 4: val (type: PT_INT32) */
	int32_t val = 0;
	if(cmd == SETVAL)
	{
		val = (int32_t)extract__syscall_argument(regs, 3);
	}
	ringbuf__store_s32(&ringbuf, val);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

SEC("tp_btf/sys_exit")
int BPF_PROG(semctl_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, SEMCTL_X_SIZE, PPME_SYSCALL_SEMCTL_X))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	ringbuf__store_s64(&ringbuf, (int64_t)ret);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

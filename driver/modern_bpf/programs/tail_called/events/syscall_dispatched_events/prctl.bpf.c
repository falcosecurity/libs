/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(prctl_e,
	     struct pt_regs *regs,
	     long id)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, PRCTL_E_SIZE))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf, PPME_SYSCALL_PRCTL_E);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: option (type: PT_UINT32)*/
	s32 option = (s32)extract__syscall_argument(regs, 0);
	ringbuf__store_s32(&ringbuf, (s32)option);

	/* Parameter 2: arg2 (type: PT_UINT64)*/
	s32 arg2 = (s32)extract__syscall_argument(regs, 1);
	ringbuf__store_s32(&ringbuf, (s32)arg2);

	/* Parameter 3: arg3 (type: PT_UINT64)*/
	s32 arg3 = (s32)extract__syscall_argument(regs, 2);
	ringbuf__store_s32(&ringbuf, (s32)arg3);

	/* Parameter 4: arg4 (type: PT_UINT64)*/
	s32 arg4 = (s32)extract__syscall_argument(regs, 3);
	ringbuf__store_s32(&ringbuf, (s32)arg4);

	/* Parameter 5: arg5 (type: PT_UINT64)*/
	s32 arg5 = (s32)extract__syscall_argument(regs, 4);
	ringbuf__store_s32(&ringbuf, (s32)arg5);


	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(prctl_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct ringbuf_struct ringbuf;
	//XXX the +2 is problably wrong but without it the verifier will complain
	if(!ringbuf__reserve_space(&ringbuf, PRCTL_X_SIZE+2))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf, PPME_SYSCALL_PRCTL_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO)*/
	ringbuf__store_s64(&ringbuf, (s64)ret);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/

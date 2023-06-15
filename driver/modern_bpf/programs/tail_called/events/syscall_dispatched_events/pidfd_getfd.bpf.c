/*
 * Copyright (C) 2022 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(pidfd_getfd_e,
         struct pt_regs *regs,
         long id)
{
    struct ringbuf_struct ringbuf;
    if(!ringbuf__reserve_space(&ringbuf, ctx, PIDFD_GETFD_E_SIZE, PPME_SYSCALL_PIDFD_GETFD_E))
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
int BPF_PROG(pidfd_getfd_x,
         struct pt_regs *regs,
         long ret)

{   
   
 struct ringbuf_struct ringbuf;
    if(!ringbuf__reserve_space(&ringbuf, ctx, PIDFD_GETFD_X_SIZE, PPME_SYSCALL_PIDFD_GETFD_X))
	{
		return 0;
	}

    ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/
    
    /* Parameter 1: ret (type: PT_FD) */
    ringbuf__store_s64(&ringbuf, ret);

    /* Parameter 2: pidfd (type: PT_FD) */
    s32 pidfd = (s32)extract__syscall_argument(regs, 0);
    ringbuf__store_s64(&ringbuf, (s64)pidfd);

    /* Parameter 3: targetfd (type: PT_FD) */
    s32 targetfd = (s32)extract__syscall_argument(regs, 1);
    ringbuf__store_s64(&ringbuf, (s64)targetfd);

    /* Parameter 4: flags (type: PT_FLAGS32)*/
    u32 flags = (u32)extract__syscall_argument(regs, 2);
    ringbuf__store_u32(&ringbuf, flags);

	/*=============================== COLLECT PARAMETERS  ===========================*/

    ringbuf__submit_event(&ringbuf);

    return 0;
}

/*=============================== EXIT EVENT ===========================*/
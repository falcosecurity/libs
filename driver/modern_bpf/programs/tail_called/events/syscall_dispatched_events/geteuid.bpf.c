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
int BPF_PROG(geteuid_e,
	     struct pt_regs *regs,
	     long id)
{
        struct ringbuf_struct ringbuf;
        if(!ringbuf__reserve_space(&ringbuf, ctx, GETEUID_E_SIZE, PPME_SYSCALL_GETEUID_E))
        {
                return 0;
        }

        ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(geteuid_x,
	     struct pt_regs *regs,
	     long ret)
{
        struct ringbuf_struct ringbuf;
        if(!ringbuf__reserve_space(&ringbuf, ctx, GETEUID_X_SIZE, PPME_SYSCALL_GETEUID_X))
        {
                return 0;
        }

        ringbuf__store_event_header(&ringbuf);


	/*=============================== COLLECT PARAMETERS  ===========================*/

        /* Parameter 1: euid (type: PT_UID) */
        ringbuf__store_u32(&ringbuf, (uint32_t)ret);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/

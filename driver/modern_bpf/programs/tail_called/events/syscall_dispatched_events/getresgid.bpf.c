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
int BPF_PROG(getresgid_e,
	     struct pt_regs *regs,
	     long id)
{
        struct ringbuf_struct ringbuf;
        if(!ringbuf__reserve_space(&ringbuf, ctx, GETRESGID_E_SIZE, PPME_SYSCALL_GETRESGID_E))
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
int BPF_PROG(getresgid_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct ringbuf_struct ringbuf;
        if(!ringbuf__reserve_space(&ringbuf, ctx, GETRESGID_X_SIZE, PPME_SYSCALL_GETRESGID_X))
        {
                return 0;
        }

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

        /* Parameter 1: res (type: PT_ERRNO) */
	ringbuf__store_s64(&ringbuf, ret);

	/* Parameter 2: rgid (type: PT_GID) */
	unsigned long rgid_pointer = extract__syscall_argument(regs, 0);
	gid_t rgid;
	bpf_probe_read_user((void *)&rgid, sizeof(rgid), (void *)rgid_pointer);
	ringbuf__store_u32(&ringbuf, (uint32_t)rgid);

	/* Parameter 3: egid (type: PT_GID) */
	unsigned long egid_pointer = extract__syscall_argument(regs, 1);
	gid_t egid;
	bpf_probe_read_user((void *)&egid, sizeof(egid), (void *)egid_pointer);
	ringbuf__store_u32(&ringbuf, (uint32_t)egid);

	/* Parameter 4: sgid (type: PT_GID) */
	unsigned long sgid_pointer = extract__syscall_argument(regs, 2);
	gid_t sgid;
	bpf_probe_read_user((void *)&sgid, sizeof(sgid), (void *)sgid_pointer);
	ringbuf__store_u32(&ringbuf, (uint32_t)sgid);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/

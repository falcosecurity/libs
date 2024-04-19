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
int BPF_PROG(sendfile_e,
	     struct pt_regs *regs,
	     long id)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, SENDFILE_E_SIZE, PPME_SYSCALL_SENDFILE_E))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: out_fd (type: PT_FD) */
	int32_t out_fd = (int32_t)extract__syscall_argument(regs, 0);
	ringbuf__store_s64(&ringbuf, (int64_t)out_fd);

	/* Parameter 2: in_fd (type: PT_FD) */
	int32_t in_fd = (int32_t)extract__syscall_argument(regs, 1);
	ringbuf__store_s64(&ringbuf, (int64_t)in_fd);

	/* Parameter 3: offset (type: PT_UINT64) */
	unsigned long offset = 0;
	unsigned long offset_pointer = extract__syscall_argument(regs, 2);
	bpf_probe_read_user((void *)&offset, sizeof(offset), (void *)offset_pointer);
	ringbuf__store_u64(&ringbuf, offset);

	/* Parameter 4: size (type: PT_UINT64) */
	uint64_t size = extract__syscall_argument(regs, 3);
	ringbuf__store_u64(&ringbuf, size);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(sendfile_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, SENDFILE_X_SIZE, PPME_SYSCALL_SENDFILE_X))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	ringbuf__store_s64(&ringbuf, ret);

	/* Parameter 2: offset (type: PT_UINT64) */
	unsigned long offset = 0;
	unsigned long offset_pointer = extract__syscall_argument(regs, 2);
	bpf_probe_read_user((void *)&offset, sizeof(offset), (void *)offset_pointer);
	ringbuf__store_u64(&ringbuf, offset);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/

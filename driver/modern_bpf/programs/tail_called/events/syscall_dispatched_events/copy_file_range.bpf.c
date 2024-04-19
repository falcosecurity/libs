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
int BPF_PROG(copy_file_range_e,
	     struct pt_regs *regs,
	     long id)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, COPY_FILE_RANGE_E_SIZE, PPME_SYSCALL_COPY_FILE_RANGE_E))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: fdin (type: PT_FD) */
	int32_t fdin = (int32_t)extract__syscall_argument(regs, 0);
	ringbuf__store_s64(&ringbuf, (int64_t)fdin);

	/* Parameter 2: offin (type: PT_UINT64) */
	uint64_t offin = extract__syscall_argument(regs, 1);
	ringbuf__store_u64(&ringbuf, offin);

	/* Parameter 3: len (type: PT_UINT64) */
	uint64_t len = extract__syscall_argument(regs, 4);
	ringbuf__store_u64(&ringbuf, len);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(copy_file_range_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, COPY_FILE_RANGE_X_SIZE, PPME_SYSCALL_COPY_FILE_RANGE_X))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO)*/
	ringbuf__store_s64(&ringbuf, ret);

	/* Parameter 2: fdout (type: PT_FD) */
	int32_t fdout = (int32_t)extract__syscall_argument(regs, 2);
	ringbuf__store_s64(&ringbuf, (int64_t)fdout);

	/* Parameter 3: offout (type: PT_UINT64) */
	uint64_t offout = extract__syscall_argument(regs, 3);
	ringbuf__store_u64(&ringbuf, offout);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/

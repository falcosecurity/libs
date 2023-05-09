/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>
#include <helpers/interfaces/variable_size_event.h>

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(pwritev_e,
	     struct pt_regs *regs,
	     long id)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, PWRITEV_E_SIZE, PPME_SYSCALL_PWRITEV_E))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: fd (type: PT_FD) */
	s32 fd = (s32)extract__syscall_argument(regs, 0);
	ringbuf__store_s64(&ringbuf, (s64)fd);

	unsigned long iov_pointer = extract__syscall_argument(regs, 1);
	unsigned long iov_cnt = extract__syscall_argument(regs, 2);

	/* Parameter 2: size (type: PT_UINT32) */
	ringbuf__store_iovec_size_param(&ringbuf, iov_pointer, iov_cnt);

	/* Parameter 3: pos (type: PT_UINT64) */
	u64 pos = (u64)extract__syscall_argument(regs, 3);
	ringbuf__store_u64(&ringbuf, pos);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(pwritev_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SYSCALL_PWRITEV_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	auxmap__store_s64_param(auxmap, ret);

	/* In case of failure `bytes_to_read` could be also lower than `snaplen`
	 * but we will discover it directly into `auxmap__store_iovec_data_param`
	 * otherwise we need to extract it now and it has a cost. Here we check just
	 * the return value if the syscall is successful.
	 */
	u16 snaplen = maps__get_snaplen();
	apply_dynamic_snaplen(regs, &snaplen, true);
	if(ret > 0 && snaplen > ret)
	{
		snaplen = ret;
	}

	unsigned long iov_pointer = extract__syscall_argument(regs, 1);
	unsigned long iov_cnt = extract__syscall_argument(regs, 2);

	/* Parameter 2: data (type: PT_BYTEBUF) */
	auxmap__store_iovec_data_param(auxmap, iov_pointer, iov_cnt, snaplen);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap, ctx);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/

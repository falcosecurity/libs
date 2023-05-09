/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(nanosleep_e,
	     struct pt_regs *regs,
	     long id)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, NANOSLEEP_E_SIZE, PPME_SYSCALL_NANOSLEEP_E))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: req (type: PT_RELTIME) */
	u64 nanosec = 0;
	unsigned long ts_pointer = extract__syscall_argument(regs, 0);
	if(bpf_core_type_exists(struct __kernel_timespec))
	{
		struct __kernel_timespec ts = {0};
		bpf_probe_read_user(&ts, bpf_core_type_size(struct __kernel_timespec), (void *)ts_pointer);
		nanosec = ((u64)ts.tv_sec) * SECOND_TO_NS + ts.tv_nsec;
	}
	else
	{
		struct modern_bpf__kernel_timespec ts = {0};
		bpf_probe_read_user(&ts, sizeof(ts), (void *)ts_pointer);
		nanosec = ((u64)ts.tv_sec) * SECOND_TO_NS + ts.tv_nsec;
	}
	ringbuf__store_u64(&ringbuf, nanosec);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(nanosleep_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, NANOSLEEP_X_SIZE, PPME_SYSCALL_NANOSLEEP_X))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	ringbuf__store_s64(&ringbuf, ret);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/

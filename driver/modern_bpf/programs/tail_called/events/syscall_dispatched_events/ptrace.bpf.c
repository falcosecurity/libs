// SPDX-License-Identifier: GPL-2.0-only OR MIT
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
int BPF_PROG(ptrace_e,
	     struct pt_regs *regs,
	     long id)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, PTRACE_E_SIZE, PPME_SYSCALL_PTRACE_E))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: request (type: PT_FLAGS16) */
	unsigned long request = extract__syscall_argument(regs, 0);
	ringbuf__store_u16(&ringbuf, ptrace_requests_to_scap(request));

	/* Parameter 2: pid (type: PT_PID) */
	pid_t pid = (int32_t)extract__syscall_argument(regs, 1);
	ringbuf__store_s64(&ringbuf, (int64_t)pid);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(ptrace_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SYSCALL_PTRACE_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	auxmap__store_s64_param(auxmap, ret);

	/* We need the ptrace request type to understand how to parse `addr` and `data` */
	unsigned long request = extract__syscall_argument(regs, 0);
	uint16_t scap_ptrace_request = ptrace_requests_to_scap(request);

	/* Parameter 2: addr (type: PT_DYN) */
	uint64_t addr_pointer = (uint64_t)extract__syscall_argument(regs, 2);
	auxmap__store_ptrace_addr_param(auxmap, ret, addr_pointer);

	/* Parameter 3: data (type: PT_DYN) */
	uint64_t data_pointer = (uint64_t)extract__syscall_argument(regs, 3);
	auxmap__store_ptrace_data_param(auxmap, ret, scap_ptrace_request, data_pointer);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap, ctx);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/

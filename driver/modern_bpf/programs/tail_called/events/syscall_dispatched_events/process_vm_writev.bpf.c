// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2024 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>
#include <helpers/interfaces/variable_size_event.h>

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(process_vm_writev_e,
	     struct pt_regs *regs,
	     long id)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, PROCESS_VM_WRITEV_E_SIZE, PPME_SYSCALL_PROCESS_VM_WRITEV_E))
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
int BPF_PROG(process_vm_writev_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SYSCALL_PROCESS_VM_WRITEV_X);


	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_INT64) */
	auxmap__store_s64_param(auxmap, ret);

	/* Parameter 2: pid (type: PT_PID) */
	int64_t pid = extract__syscall_argument(regs, 0);
	auxmap__store_s64_param(auxmap, pid);

	if(ret > 0)
	{
		/* We read the minimum between `snaplen` and what we really
		 * have in the buffer.
		 */
		uint16_t snaplen = maps__get_snaplen();
		apply_dynamic_snaplen(regs, &snaplen, true);
		if(snaplen > ret)
		{
			snaplen = ret;
		}

		unsigned long iov_pointer = extract__syscall_argument(regs, 1);
		unsigned long iov_cnt = extract__syscall_argument(regs, 2);

		//* Parameter 3: data (type: PT_BYTEBUF) */
		auxmap__store_iovec_data_param(auxmap, iov_pointer, iov_cnt, snaplen);
	}
	else
	{
		/* Parameter 3: data (type: PT_BYTEBUF) */
		auxmap__store_empty_param(auxmap);
	}

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap, ctx);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/

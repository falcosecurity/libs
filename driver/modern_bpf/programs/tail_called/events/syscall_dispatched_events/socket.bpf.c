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
int BPF_PROG(socket_e,
	     struct pt_regs *regs,
	     long id)
{
	/* Collect parameters at the beginning so we can easily manage socketcalls */
	unsigned long args[3] = {0};
	extract__network_args(args, 3, regs);

	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, SOCKET_E_SIZE, PPME_SOCKET_SOCKET_E))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: domain (type: PT_ENUMFLAGS32) */
	/* why to send 32 bits if we need only 8 bits? */
	uint8_t domain = (uint8_t)args[0];
	ringbuf__store_u32(&ringbuf, (uint32_t)socket_family_to_scap(domain));

	/* Parameter 2: type (type: PT_UINT32) */
	/* this should be an int, not a uint32 */
	uint32_t type = (uint32_t)args[1];
	ringbuf__store_u32(&ringbuf, type);

	/* Parameter 3: proto (type: PT_UINT32) */
	/* this should be an int, not a uint32 */
	uint32_t proto = (uint32_t)args[2];
	ringbuf__store_u32(&ringbuf, proto);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(socket_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, SOCKET_X_SIZE, PPME_SOCKET_SOCKET_X))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO)*/
	ringbuf__store_s64(&ringbuf, ret);

	/* Just called once by our scap process */
	if(ret >= 0 && maps__get_socket_file_ops() == NULL)
	{
		struct task_struct *task = get_current_task();
		/* Please note that in `g_settings.scap_tid` scap will put its virtual tid
		 * if it is running inside a container. If we want to extract the same information
		 * in the kernel we need to extract the virtual tid of the task.
		 */
		pid_t vtid = extract__task_xid_vnr(task, PIDTYPE_PID);
		/* it means that scap is performing the calibration */
		if(vtid == maps__get_scap_tid())
		{
			struct file *f = extract__file_struct_from_fd(ret);
			if(f)
			{
				struct file_operations *f_op = (struct file_operations *)BPF_CORE_READ(f, f_op);
				maps__set_socket_file_ops((void*)f_op);
				/* we need to rewrite the event header */
				ringbuf__rewrite_header_for_calibration(&ringbuf, vtid);
			}
		}
	}

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/

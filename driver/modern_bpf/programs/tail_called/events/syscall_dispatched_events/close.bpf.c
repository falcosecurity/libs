/*
 * Copyright (C) 2022 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(close_e,
	     struct pt_regs *regs,
	     long id)
{
	if(maps__get_dropping_mode())
	{
		s32 fd = (s32)extract__syscall_argument(regs, 0);
		/* We drop the event if we are closing a negative file descriptor */
		if(fd < 0)
		{
			return 0;
		}

		struct task_struct *task = get_current_task();
		u32 max_fds = 0;
		BPF_CORE_READ_INTO(&max_fds, task, files, fdt, max_fds);
		/* We drop the event if the fd is >= than `max_fds` */
		if(fd >= max_fds)
		{
			return 0;
		}

		/* We drop the event if the fd is not open */
		long unsigned int entry = 0;
		long unsigned int *open_fds = BPF_CORE_READ(task, files, fdt, open_fds);
		if(open_fds == NULL)
		{
			return 0;
		}
		if(bpf_probe_read_kernel(&entry, sizeof(entry), (const void *)&(open_fds[BIT_WORD(fd)])) == 0)
		{
			if(!(1UL & (entry >> (fd & (BITS_PER_LONG - 1)))))
			{
				return 0;
			}
		}
	}

	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, CLOSE_E_SIZE, PPME_SYSCALL_CLOSE_E))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: fd (type: PT_FD)*/
	s32 fd = (s32)extract__syscall_argument(regs, 0);
	ringbuf__store_s64(&ringbuf, (s64)fd);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(close_x,
	     struct pt_regs *regs,
	     long ret)
{
	if(maps__get_dropping_mode() && ret < 0)
	{
		return 0;
	}

	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, CLOSE_X_SIZE, PPME_SYSCALL_CLOSE_X))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO)*/
	ringbuf__store_s64(&ringbuf, ret);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/

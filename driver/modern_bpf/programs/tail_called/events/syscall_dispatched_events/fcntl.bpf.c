/*
 * Copyright (C) 2022 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>

static __always_inline bool check_fcntl_dropping(struct pt_regs *regs)
{
	int cmd = (s32)extract__syscall_argument(regs, 1);
	if(cmd != F_DUPFD && cmd != F_DUPFD_CLOEXEC)
	{
		return true;
	}
	return false;
}

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(fcntl_e,
	     struct pt_regs *regs,
	     long id)
{
	if(maps__get_dropping_mode() && check_fcntl_dropping(regs))
	{
		return 0;
	}

	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, FCNTL_E_SIZE, PPME_SYSCALL_FCNTL_E))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: fd (type: PT_FD) */
	s32 fd = (s32)extract__syscall_argument(regs, 0);
	ringbuf__store_s64(&ringbuf, (s64)fd);

	/* Parameter 2: cmd (type: PT_ENUMFLAGS8) */
	int cmd = (s32)extract__syscall_argument(regs, 1);
	ringbuf__store_u8(&ringbuf, fcntl_cmd_to_scap(cmd));

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(fcntl_x,
	     struct pt_regs *regs,
	     long ret)
{
	if(maps__get_dropping_mode() && check_fcntl_dropping(regs))
	{
		return 0;
	}

	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, FCNTL_X_SIZE, PPME_SYSCALL_FCNTL_X))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_FD)*/
	ringbuf__store_s64(&ringbuf, ret);

	/* Parameter 2: fd (type: PT_FD) */
	s32 fd = (s32)extract__syscall_argument(regs, 0);
	ringbuf__store_s64(&ringbuf, (s64)fd);

	/* Parameter 3: cmd (type: PT_ENUMFLAGS8) */
	int cmd = (s32)extract__syscall_argument(regs, 1);
	ringbuf__store_u8(&ringbuf, fcntl_cmd_to_scap(cmd));

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/

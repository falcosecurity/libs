// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/syscalls_dispatcher.h>
#include <helpers/interfaces/attached_programs.h>

/* From linux tree: /include/trace/events/syscall.h
 * TP_PROTO(struct pt_regs *regs, long id),
 */
SEC("tp_btf/sys_enter")
int BPF_PROG(sys_enter,
	     struct pt_regs *regs,
	     long syscall_id)
{

	if(syscalls_dispatcher__check_32bit_syscalls())
	{
#if defined(__TARGET_ARCH_x86)
		syscall_id = syscalls_dispatcher__convert_ia32_to_64(syscall_id);
		if(syscall_id == (u32)-1)
		{
			return 0;
		}
#else
		// TODO: unsupported
		return 0;
#endif
	}

#ifdef CAPTURE_SOCKETCALL
	/* we convert it here in this way the syscall will be treated exactly as the original one */
	if(syscall_id == __NR_socketcall)
	{
		syscall_id = convert_network_syscalls(regs);
	}
#endif

	if(!syscalls_dispatcher__64bit_interesting_syscall(syscall_id))
	{
		return 0;
	}

	if(sampling_logic(ctx, syscall_id, SYSCALL))
	{
		return 0;
	}



	bpf_tail_call(ctx, &syscall_enter_tail_table, syscall_id);
	return 0;
}

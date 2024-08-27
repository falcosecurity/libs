// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/syscalls_dispatcher.h>
#include <helpers/interfaces/attached_programs.h>
#include <bpf/bpf_helpers.h>

#define X86_64_NR_EXECVE        59
#define X86_64_NR_EXECVEAT      322

/* From linux tree: /include/trace/events/syscall.h
 * TP_PROTO(struct pt_regs *regs, long ret),
 */
SEC("tp_btf/sys_exit")
int BPF_PROG(sys_exit,
	     struct pt_regs *regs,
	     long ret)
{
	int socketcall_syscall_id = -1;

	uint32_t syscall_id = extract__syscall_id(regs);

	if(bpf_in_ia32_syscall())
	{
#if defined(__TARGET_ARCH_x86)
		if (syscall_id == __NR_ia32_socketcall)
		{
			socketcall_syscall_id = __NR_ia32_socketcall;
		}
		else
		{
			/*
			 * When a process does execve from 64bit to 32bit, TS_COMPAT is marked true
			 * but the id of the syscall is __NR_execve, so to correctly parse it we need to
			 * use 64bit syscall table. On 32bit __NR_execve is equal to __NR_ia32_oldolduname
			 * which is a very old syscall, not used anymore by most applications
			 */
			if(syscall_id != X86_64_NR_EXECVE && syscall_id != X86_64_NR_EXECVEAT)
			{
				syscall_id = maps__ia32_to_64(syscall_id);
				if(syscall_id == (uint32_t)-1)
				{
					return 0;
				}
			}
		}
#else
			// TODO: unsupported
			return 0;
#endif
	}
	else
	{
#ifdef __NR_socketcall
		socketcall_syscall_id = __NR_socketcall;
#endif
	}

	/* we convert it here in this way the syscall will be treated exactly as the original one */
	if(syscall_id == socketcall_syscall_id)
	{
		syscall_id = convert_network_syscalls(regs);
		if (syscall_id == -1)
		{
			// We can't do anything since modern bpf filler jump table is syscall indexed
			return 0;
		}
	}

	if(!syscalls_dispatcher__64bit_interesting_syscall(syscall_id))
	{
		return 0;
	}

	if(sampling_logic(ctx, syscall_id, MODERN_BPF_SYSCALL))
	{
		return 0;
	}

	if (maps__get_drop_failed() && ret < 0)
	{
		return 0;
	}

	bpf_tail_call(ctx, &syscall_exit_tail_table, syscall_id);

	return 0;
}

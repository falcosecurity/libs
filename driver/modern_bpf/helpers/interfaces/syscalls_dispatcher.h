/*
 * Copyright (C) 2022 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#pragma once

/* Syscall dispatcher programs are always attached programs. */
#include <helpers/base/maps_getters.h>
#include <helpers/base/read_from_task.h>

static __always_inline u32 syscalls_dispatcher__get_syscall_id(struct pt_regs *regs)
{
#if defined(__TARGET_ARCH_x86)
	return (u32)regs->orig_ax;
#elif defined(__TARGET_ARCH_arm64)
	return (u32)regs->syscallno;
#elif defined(__TARGET_ARCH_s390)
	return (u32)regs->int_code & 0xffff;
#else
	return 0;
#endif
}

static __always_inline bool syscalls_dispatcher__check_32bit_syscalls()
{
	uint32_t status;
	struct task_struct *task = get_current_task();

#if defined(__TARGET_ARCH_x86)
	READ_TASK_FIELD_INTO(&status, task, thread_info.status);
	return status & TS_COMPAT;
#elif defined(__TARGET_ARCH_arm64)
	READ_TASK_FIELD_INTO(&status, task, thread_info.flags);
	return status & _TIF_32BIT;
#elif defined(__TARGET_ARCH_s390)
	READ_TASK_FIELD_INTO(&status, task, thread_info.flags);
	return status & _TIF_31BIT;
#else
	return false;
#endif
}

static __always_inline bool syscalls_dispatcher__64bit_interesting_syscall(u32 syscall_id)
{
	return maps__64bit_interesting_syscall(syscall_id);
}

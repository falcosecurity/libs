#pragma once

/* Syscall dispatcher programs are always attached programs. */
#include "../base/maps_getters.h"
#include "../base/read_from_task.h"

static __always_inline u32 syscalls_dispatcher__get_syscall_id(struct pt_regs *regs)
{
#if defined(__TARGET_ARCH_x86)
	return (u32)regs->orig_ax;
#elif defined(__TARGET_ARCH_aarch64)
	return (u32)regs->syscallno;
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
#elif defined(__TARGET_ARCH_aarch64)
	READ_TASK_FIELD_INTO(&status, task, thread_info.flags);
	return status & _TIF_32BIT;
#else
	return false;
#endif
}

static __always_inline bool syscalls_dispatcher__64bit_interesting_syscall(u32 syscall_id)
{
	return maps__64bit_interesting_syscall(syscall_id);
}

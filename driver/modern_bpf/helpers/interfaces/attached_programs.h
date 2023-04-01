/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#pragma once

#include <helpers/base/maps_getters.h>

/* This enum is used to tell if we are considering a syscall or a tracepoint */
enum intrumentation_type
{
	SYSCALL = 0,
	TRACEPOINT = 1,
};

/* The sampling logic is used by all BPF programs attached to the kernel.
 * We treat the syscalls tracepoints in a dedicated way because they could generate
 * more than one event (1 for each syscall) for this reason we need a dedicated table.
 */
static __always_inline bool sampling_logic(void* ctx, u32 id, enum intrumentation_type type)
{
	/* If dropping mode is not enabled we don't perform any sampling
	 * false: means don't drop the syscall
	 * true: means drop the syscall
	 */
	if(!maps__get_dropping_mode())
	{
		return false;
	}

	uint8_t sampling_flag = 0;

	/* If we have a syscall we use the sampling_syscall_table otherwise
	 * with tracepoints we use the sampling_tracepoint_table.
	 */
	if(type == SYSCALL)
	{
		sampling_flag = maps__64bit_sampling_syscall_table(id);
	}
	else
	{
		sampling_flag = maps__64bit_sampling_tracepoint_table(id);
	}

	if(sampling_flag == UF_NEVER_DROP)
	{
		return false;
	}

	if(sampling_flag == UF_ALWAYS_DROP)
	{
		return true;
	}

	if((bpf_ktime_get_boot_ns() % SECOND_TO_NS) >= (SECOND_TO_NS / maps__get_sampling_ratio()))
	{
		/* If we are starting the dropping phase we need to notify the userspace, otherwise, we
		 * simply drop our event.
		 * PLEASE NOTE: this logic is not per-CPU so it is best effort!
		 */
		if(!maps__get_is_dropping())
		{
			/* Here we are not sure we can send the drop_e event to userspace
			 * if the buffer is full, but this is not essential even if we lose
			 * an iteration we will synchronize again the next time the logic is enabled.
			 */
			maps__set_is_dropping(true);
			bpf_tail_call(ctx, &extra_event_prog_tail_table, T1_DROP_E);
			bpf_printk("unable to tail call into 'drop_e' prog");
		}
		return true;
	}

	if(maps__get_is_dropping())
	{
		maps__set_is_dropping(false);
		bpf_tail_call(ctx, &extra_event_prog_tail_table, T1_DROP_X);
		bpf_printk("unable to tail call into 'drop_x' prog");
	}

	return false;
}

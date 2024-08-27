// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>
#include <helpers/interfaces/attached_programs.h>

/* From linux tree: /include/linux/events/sched.h
 * TP_PROTO(bool preempt, struct task_struct *prev,
 *		 struct task_struct *next)
 */
SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch,
	     bool preempt, struct task_struct *prev,
	     struct task_struct *next)
{
	if(sampling_logic(ctx, PPME_SCHEDSWITCH_6_E, MODERN_BPF_TRACEPOINT))
	{
		return 0;
	}
	
	/// TODO: we could avoid switches from kernel threads to kernel threads (?).

	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, SCHED_SWITCH_SIZE, PPME_SCHEDSWITCH_6_E))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: next (type: PT_PID) */
	int64_t pid = (int64_t)extract__task_xid_nr(next, PIDTYPE_PID);
	ringbuf__store_s64(&ringbuf, (int64_t)pid);

	/* Parameter 2: pgft_maj (type: PT_UINT64) */
	unsigned long pgft_maj = 0;
	extract__pgft_maj(prev, &pgft_maj);
	ringbuf__store_u64(&ringbuf, pgft_maj);

	/* Parameter 3: pgft_min (type: PT_UINT64) */
	unsigned long pgft_min = 0;
	extract__pgft_min(prev, &pgft_min);
	ringbuf__store_u64(&ringbuf, pgft_min);

	struct mm_struct *mm = NULL;
	READ_TASK_FIELD_INTO(&mm, prev, mm);

	/* Parameter 4: vm_size (type: PT_UINT32) */
	uint32_t vm_size = extract__vm_size(mm);
	ringbuf__store_u32(&ringbuf, vm_size);

	/* Parameter 5: vm_rss (type: PT_UINT32) */
	uint32_t vm_rss = extract__vm_rss(mm);
	ringbuf__store_u32(&ringbuf, vm_rss);

	/* Parameter 6: vm_swap (type: PT_UINT32) */
	uint32_t vm_swap = extract__vm_swap(mm);
	ringbuf__store_u32(&ringbuf, vm_swap);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

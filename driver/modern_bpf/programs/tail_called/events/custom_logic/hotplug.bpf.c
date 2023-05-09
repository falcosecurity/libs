/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>

SEC("tp_btf/sys_enter")
int BPF_PROG(t1_hotplug_e)
{
	/* We assume that the ring buffer for CPU 0 is always there so we send the
	 * HOT-PLUG event through this buffer.
	 */
	u32 cpu_0 = 0;
	struct ringbuf_map *rb = bpf_map_lookup_elem(&ringbuf_maps, &cpu_0);
	if(!rb)
	{
		bpf_printk("unable to obtain the ring buffer for CPU 0");
		return 0;
	}

	struct counter_map *counter = bpf_map_lookup_elem(&counter_maps, &cpu_0);
	if(!counter)
	{
		bpf_printk("unable to obtain the counter map for CPU 0");
		return 0;
	}

	/* This counts the event seen by the drivers even if they are dropped because the buffer is full. */
	counter->n_evts++;

	/* If we are not able to reserve space we stop here
	 * the event collection.
	 */
	struct ringbuf_struct ringbuf;
	ringbuf.reserved_event_size = HOTPLUG_E_SIZE;
	ringbuf.event_type = PPME_CPU_HOTPLUG_E;
	ringbuf.data = bpf_ringbuf_reserve(rb, HOTPLUG_E_SIZE, 0);
	if(!ringbuf.data)
	{
		counter->n_drops_buffer++;
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS ===========================*/

	/* Parameter 1: cpu (type: PT_UINT32) */
	u32 current_cpu_id = (u32)bpf_get_smp_processor_id();
	ringbuf__store_u32(&ringbuf, current_cpu_id);

	/* Parameter 2: action (type: PT_UINT32) */
	/* Right now we don't have actions we always send 0 */
	ringbuf__store_u32(&ringbuf, 0);

	/*=============================== COLLECT PARAMETERS ===========================*/

	ringbuf__submit_event(&ringbuf);
	return 0;
}

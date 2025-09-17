// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(generic_x, struct pt_regs *regs, long ret) {
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, SYSCALL_X_SIZE, PPME_GENERIC_X)) {
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS ===========================*/

	uint32_t id = extract__syscall_id(regs);
	// We are already in a tail-called filler. If we are in ia-32 syscall sys_exit already validated
	// the converted 32bit->64bit syscall ID for us, otherwise the event would've been discarded.
#if defined(__TARGET_ARCH_x86)
	if(bpf_in_ia32_syscall()) {
		id = maps__ia32_to_64(id);
	}
#endif

	/* Parameter 1: ID (type: PT_SYSCALLID) */
	/* This is the PPM_SC code obtained from the syscall id. */
	ringbuf__store_u16(&ringbuf, maps__get_ppm_sc(id));

	/* Parameter 2: nativeID (type: PT_UINT16) */
	ringbuf__store_u16(&ringbuf, id);

	/*=============================== COLLECT PARAMETERS ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/

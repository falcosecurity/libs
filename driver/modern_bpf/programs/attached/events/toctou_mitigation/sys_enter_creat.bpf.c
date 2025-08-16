// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2025 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/toctou_mitigation.h>
#include <helpers/interfaces/variable_size_event.h>

static __always_inline void submit_creat_enter_event(struct auxiliary_map* auxmap,
                                                     unsigned long pathname_pointer,
                                                     unsigned long mode) {
	auxmap__preload_event_header(auxmap, PPME_SYSCALL_CREAT_E);

	/*=============================== STORE PARAMETERS  ===========================*/

	/* Parameter 1: name (type: PT_FSPATH) */
	auxmap__store_charbuf_param(auxmap, pathname_pointer, MAX_PATH, USER);

	/* Parameter 2: mode (type: PT_UINT32) */
	auxmap__store_u32_param(auxmap, open_modes_to_scap(O_CREAT, mode));

	/*=============================== STORE PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);
}

/*=========================== COMMON 64BIT SUPPORT (TRACEPOINT-BASED) =======================*/

// This struct is defined according to the following format file:
// /sys/kernel/tracing/events/syscalls/sys_enter_creat/format
struct sys_enter_creat_args {
	uint64_t pad;

	uint32_t __syscall_nr;
	uint64_t filename;
	uint64_t mode;
};

SEC("tracepoint/syscalls/sys_enter_creat")
int creat_e(struct sys_enter_creat_args* ctx) {
	if(toctou_mitigation__64bit_should_drop(ctx->__syscall_nr, -1)) {
		return 0;
	}

	struct auxiliary_map* auxmap = auxmap__get();
	if(!auxmap) {
		return 0;
	}

	/* Extract syscall arguments from context. */
	unsigned long pathname_pointer = (unsigned long)ctx->filename;
	unsigned long mode = (unsigned long)ctx->mode;

	submit_creat_enter_event(auxmap, pathname_pointer, mode);
	return 0;
}

/*=========================== COMMON 64BIT SUPPORT (TRACEPOINT-BASED) =======================*/

/*=============================== IA-32 SUPPORT (KPROBE-BASED) ===========================*/

static __always_inline int ia32_common_handler(struct pt_regs* regs, long int retval) {
	if(toctou_mitigation__ia32_should_drop(__NR_ia32_creat, -1)) {
		return 0;
	}

	struct auxiliary_map* auxmap = auxmap__get();
	if(!auxmap) {
		return 0;
	}

	/* Extract syscall arguments from registers. */
	unsigned long pathname_pointer = (unsigned long)extract__syscall_argument(regs, 0);
	unsigned long mode = (unsigned long)extract__syscall_argument(regs, 1);
	uint16_t usrsockaddr_len = (uint16_t)extract__syscall_argument(regs, 2);

	submit_creat_enter_event(auxmap, pathname_pointer, mode);
	return 0;
}

SEC("kprobe/__ia32_compat_sys_creat")
int BPF_KPROBE(ia32_compat_creat_e, struct pt_regs* regs, long int retval) {
	return ia32_common_handler(regs, retval);
}

SEC("kprobe/__ia32_sys_creat")
int BPF_KPROBE(ia32_creat_e, struct pt_regs* regs, long int retval) {
	return ia32_common_handler(regs, retval);
}

/*=============================== IA-32 SUPPORT (KPROBE-BASED) ===========================*/

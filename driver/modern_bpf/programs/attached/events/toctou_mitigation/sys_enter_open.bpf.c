// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2025 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/toctou_mitigation.h>
#include <helpers/interfaces/variable_size_event.h>

static __always_inline void submit_open_enter_event(struct auxiliary_map* auxmap,
                                                    unsigned long filename_pointer,
                                                    uint32_t flags,
                                                    unsigned long mode) {
	auxmap__preload_event_header(auxmap, PPME_SYSCALL_OPEN_E);

	/*=============================== STORE PARAMETERS  ===========================*/

	/* Parameter 1: name (type: PT_FSPATH) */
	auxmap__store_charbuf_param(auxmap, filename_pointer, MAX_PATH, USER);

	/* Parameter 2: flags (type: PT_FLAGS32) */
	auxmap__store_u32_param(auxmap, open_flags_to_scap(flags));

	/* Parameter 3: mode (type: PT_UINT32) */
	auxmap__store_u32_param(auxmap, open_modes_to_scap(flags, mode));

	/*=============================== STORE PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);
}

/*=============================== ENTER EVENT ===========================*/

// This struct is defined according to the following format file:
// /sys/kernel/tracing/events/syscalls/sys_enter_open/format
struct sys_enter_open_args {
	uint64_t pad1;

	uint32_t __syscall_nr;
	uint32_t pad2;
	uint64_t filename;
	uint64_t flags;
	uint64_t mode;
};

SEC("tracepoint/syscalls/sys_enter_open")
int open_e(struct sys_enter_open_args* ctx) {
	if(toctou_mitigation__64bit_should_drop(ctx->__syscall_nr, -1)) {
		return 0;
	}

	struct auxiliary_map* auxmap = auxmap__get();
	if(!auxmap) {
		return 0;
	}

	/* Extract syscall arguments from context. */
	unsigned long filename_pointer = (unsigned long)ctx->filename;
	uint32_t flags = (uint32_t)ctx->flags;
	unsigned long mode = (unsigned long)ctx->mode;

	submit_open_enter_event(auxmap, filename_pointer, flags, mode);
	return 0;
}

static __always_inline int ia32_handler(struct pt_regs* regs, long int retval) {
	if(toctou_mitigation__ia32_should_drop(__NR_ia32_open, -1)) {
		return 0;
	}

	struct auxiliary_map* auxmap = auxmap__get();
	if(!auxmap) {
		return 0;
	}

	/* Extract syscall arguments from registers. */
	unsigned long filename_pointer = (unsigned long)extract__syscall_argument(regs, 0);
	uint32_t flags = (uint32_t)extract__syscall_argument(regs, 1);
	unsigned long mode = (unsigned long)extract__syscall_argument(regs, 2);

	submit_open_enter_event(auxmap, filename_pointer, flags, mode);
	return 0;
}

SEC("fentry/__ia32_sys_open")
int BPF_PROG(ia32_open_e, struct pt_regs* regs, long int retval) {
	return ia32_handler(regs, retval);
}

SEC("fentry/__ia32_compat_sys_open")
int BPF_PROG(ia32_compat_open_e, struct pt_regs* regs, long int retval) {
	return ia32_handler(regs, retval);
}

/*=============================== ENTER EVENT ===========================*/

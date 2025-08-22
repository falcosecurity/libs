// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2025 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/toctou_mitigation.h>
#include <helpers/interfaces/variable_size_event.h>

static __always_inline void submit_openat_enter_event(struct auxiliary_map* auxmap,
                                                      int64_t dir_fd,
                                                      unsigned long filename_pointer,
                                                      uint32_t flags,
                                                      unsigned long mode) {
	auxmap__preload_event_header(auxmap, PPME_SYSCALL_OPENAT_2_E);

	/*=============================== STORE PARAMETERS  ===========================*/

	/* Parameter 1: dirfd (type: PT_FD) */
	if(dir_fd == AT_FDCWD) {
		dir_fd = PPM_AT_FDCWD;
	}
	auxmap__store_s64_param(auxmap, dir_fd);

	/* Parameter 2: name (type: PT_FSRELPATH) */
	auxmap__store_charbuf_param(auxmap, filename_pointer, MAX_PATH, USER);

	/* Parameter 3: flags (type: PT_FLAGS32) */
	auxmap__store_u32_param(auxmap, open_flags_to_scap(flags));

	/* Parameter 4: mode (type: PT_UINT32) */
	auxmap__store_u32_param(auxmap, open_modes_to_scap(flags, mode));

	/*=============================== STORE PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);
}

/*=========================== COMMON 64BIT SUPPORT (TRACEPOINT-BASED) =======================*/

// This struct is defined according to the following format file:
// /sys/kernel/tracing/events/syscalls/sys_enter_openat/format
struct sys_enter_openat_args {
	uint64_t pad1;

	uint32_t __syscall_nr;
	uint32_t pad2;
	uint64_t dfd;
	uint64_t filename;
	uint64_t flags;
	uint64_t mode;
};

SEC("tracepoint/syscalls/sys_enter_openat")
int openat_e(struct sys_enter_openat_args* ctx) {
	if(toctou_mitigation__64bit_should_drop(ctx->__syscall_nr, -1)) {
		return 0;
	}

	struct auxiliary_map* auxmap = auxmap__get();
	if(!auxmap) {
		return 0;
	}

	/* Extract syscall arguments from context. */
	int64_t dir_fd = (int64_t)(int32_t)ctx->dfd;
	unsigned long filename_pointer = (unsigned long)ctx->filename;
	uint32_t flags = (uint32_t)ctx->flags;
	unsigned long mode = ctx->mode;

	submit_openat_enter_event(auxmap, dir_fd, filename_pointer, flags, mode);
	return 0;
}

/*=========================== COMMON 64BIT SUPPORT (TRACEPOINT-BASED) =======================*/

/*=============================== IA-32 SUPPORT (KPROBE-BASED) ===========================*/

static __always_inline int ia32_common_handler(struct pt_regs* regs) {
	if(toctou_mitigation__ia32_should_drop(__NR_ia32_openat, -1)) {
		return 0;
	}

	struct auxiliary_map* auxmap = auxmap__get();
	if(!auxmap) {
		return 0;
	}

	/* Extract syscall arguments from registers. */
	int64_t dir_fd = (int64_t)(int32_t)extract__syscall_argument(regs, 0);
	unsigned long filename_pointer = (unsigned long)extract__syscall_argument(regs, 1);
	uint32_t flags = (uint32_t)extract__syscall_argument(regs, 2);
	unsigned long mode = extract__syscall_argument(regs, 3);

	submit_openat_enter_event(auxmap, dir_fd, filename_pointer, flags, mode);
	return 0;
}

SEC("kprobe/__ia32_compat_sys_openat")
int BPF_KPROBE(ia32_compat_openat_e, struct pt_regs* regs) {
	return ia32_common_handler(regs);
}

SEC("kprobe/__ia32_sys_openat")
int BPF_KPROBE(ia32_openat_e, struct pt_regs* regs) {
	return ia32_common_handler(regs);
}

/*=============================== IA-32 SUPPORT (KPROBE-BASED) ===========================*/

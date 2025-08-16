// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2025 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/toctou_mitigation.h>
#include <helpers/interfaces/variable_size_event.h>

static __always_inline void submit_openat2_enter_event(struct auxiliary_map *auxmap,
                                                       int64_t dir_fd,
                                                       unsigned long filename_pointer,
                                                       unsigned long how_pointer) {
	auxmap__preload_event_header(auxmap, PPME_SYSCALL_OPENAT2_E);

	/*=============================== STORE PARAMETERS  ===========================*/

	/* Parameter 1: dirfd (type: PT_FD) */
	if(dir_fd == AT_FDCWD) {
		dir_fd = PPM_AT_FDCWD;
	}
	auxmap__store_s64_param(auxmap, dir_fd);

	/* Parameter 2: name (type: PT_FSRELPATH) */
	auxmap__store_charbuf_param(auxmap, filename_pointer, MAX_PATH, USER);

	/* The `open_how` struct is defined since kernel version 5.6. */
	struct open_how how = {0};
	bpf_probe_read_user((void *)&how, bpf_core_type_size(struct open_how), (void *)how_pointer);

	/* Parameter 3: flags (type: PT_FLAGS32) */
	auxmap__store_u32_param(auxmap, open_flags_to_scap(how.flags));

	/* Parameter 4: mode (type: PT_UINT32) */
	auxmap__store_u32_param(auxmap, open_modes_to_scap(how.flags, how.mode));

	/* Parameter 5: resolve (type: PT_FLAGS32) */
	auxmap__store_u32_param(auxmap, openat2_resolve_to_scap(how.resolve));

	/*=============================== STORE PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);
}

/*=========================== COMMON 64BIT SUPPORT (TRACEPOINT-BASED) =======================*/

// This struct is defined according to the following format file:
// /sys/kernel/tracing/events/syscalls/sys_enter_openat2/format
struct sys_enter_openat2_args {
	uint64_t pad1;

	uint32_t __syscall_nr;
	uint32_t pad2;
	uint64_t dfd;
	uint64_t filename;
	uint64_t how;
	uint64_t usize;
};

SEC("tracepoint/syscalls/sys_enter_openat2")
int openat2_e(struct sys_enter_openat2_args *ctx) {
	if(toctou_mitigation__64bit_should_drop(ctx->__syscall_nr, -1)) {
		return 0;
	}

	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap) {
		return 0;
	}

	/* Extract syscall arguments from context. */
	int64_t dir_fd = (int64_t)(int32_t)ctx->dfd;
	unsigned long filename_pointer = (unsigned long)ctx->filename;
	unsigned long how_pointer = (unsigned long)ctx->how;

	submit_openat2_enter_event(auxmap, dir_fd, filename_pointer, how_pointer);
	return 0;
}

/*=========================== COMMON 64BIT SUPPORT (TRACEPOINT-BASED) =======================*/

/*=============================== IA-32 SUPPORT (KPROBE-BASED) ===========================*/

static __always_inline int ia32_common_handler(struct pt_regs *regs, long int retval) {
	if(toctou_mitigation__ia32_should_drop(__NR_ia32_openat2, -1)) {
		return 0;
	}

	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap) {
		return 0;
	}

	/* Extract syscall arguments from registers. */
	int64_t dir_fd = (int64_t)(int32_t)extract__syscall_argument(regs, 0);
	unsigned long filename_pointer = (unsigned long)extract__syscall_argument(regs, 1);
	unsigned long how_pointer = (unsigned long)extract__syscall_argument(regs, 2);

	submit_openat2_enter_event(auxmap, dir_fd, filename_pointer, how_pointer);
	return 0;
}

SEC("kprobe/__ia32_compat_sys_openat2")
int BPF_KPROBE(ia32_compat_openat2_e, struct pt_regs *regs, long int retval) {
	return ia32_common_handler(regs, retval);
}

SEC("kprobe/__ia32_sys_openat2")
int BPF_KPROBE(ia32_openat2_e, struct pt_regs *regs, long int retval) {
	return ia32_common_handler(regs, retval);
}

/*=============================== IA-32 SUPPORT (KPROBE-BASED) ===========================*/

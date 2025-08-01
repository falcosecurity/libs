// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2025 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/toctou_mitigation.h>
#include <helpers/interfaces/variable_size_event.h>

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

/*=============================== ENTER DISPATCHER ===========================*/

SEC("tracepoint/syscalls/sys_enter_openat")
int openat_e(struct sys_enter_openat_args* ctx) {
	return toctou_mitigation__call_prog(ctx, ctx->__syscall_nr, -1, TTM_OPENAT_E);
}

/*=============================== ENTER DISPATCHER ===========================*/

/*=============================== ENTER EVENT ===========================*/

SEC("tracepoint/syscalls/sys_enter_openat")
int ttm_openat_e(struct sys_enter_openat_args* ctx) {
	struct auxiliary_map* auxmap = auxmap__get();
	if(!auxmap) {
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SYSCALL_OPENAT_2_E);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: dirfd (type: PT_FD) */
	int64_t dirfd = (int64_t)(int32_t)ctx->dfd;
	if(dirfd == AT_FDCWD) {
		dirfd = PPM_AT_FDCWD;
	}
	auxmap__store_s64_param(auxmap, dirfd);

	/* Parameter 2: name (type: PT_FSRELPATH) */
	unsigned long path_pointer = (unsigned long)ctx->filename;
	auxmap__store_charbuf_param(auxmap, path_pointer, MAX_PATH, USER);

	/* Parameter 3: flags (type: PT_FLAGS32) */
	uint32_t flags = (uint32_t)ctx->flags;
	auxmap__store_u32_param(auxmap, open_flags_to_scap(flags));

	/* Parameter 4: mode (type: PT_UINT32) */
	unsigned long mode = ctx->mode;
	auxmap__store_u32_param(auxmap, open_modes_to_scap(flags, mode));

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/variable_size_event.h>

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(openat_x, struct pt_regs *regs, long ret) {
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap) {
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SYSCALL_OPENAT_2_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	dev_t dev = 0;
	uint64_t ino = 0;
	enum ppm_overlay ol = PPM_NOT_OVERLAY_FS;

	if(ret > 0) {
		extract__dev_ino_overlay_from_fd(ret, &dev, &ino, &ol);
	}

	/* Parameter 1: fd (type: PT_FD) */
	auxmap__store_s64_param(auxmap, ret);

	/* Parameter 2: dirfd (type: PT_FD) */
	int32_t dirfd = (int32_t)extract__syscall_argument(regs, 0);
	if(dirfd == AT_FDCWD) {
		dirfd = PPM_AT_FDCWD;
	}
	auxmap__store_s64_param(auxmap, (int64_t)dirfd);

	/* Parameter 3: name (type: PT_FSRELPATH) */
	unsigned long path_pointer = extract__syscall_argument(regs, 1);
	auxmap__store_charbuf_param(auxmap, path_pointer, MAX_PATH, USER);

	/* Parameter 4: flags (type: PT_FLAGS32) */
	uint32_t flags = (uint32_t)extract__syscall_argument(regs, 2);
	uint32_t scap_flags = (uint32_t)open_flags_to_scap(flags);
	/* update flags if file is created */
	scap_flags |= extract__fmode_created_from_fd(ret);
	if(ol == PPM_OVERLAY_UPPER) {
		scap_flags |= PPM_FD_UPPER_LAYER;
	} else if(ol == PPM_OVERLAY_LOWER) {
		scap_flags |= PPM_FD_LOWER_LAYER;
	}
	auxmap__store_u32_param(auxmap, scap_flags);

	/* Parameter 5: mode (type: PT_UINT32) */
	unsigned long mode = extract__syscall_argument(regs, 3);
	auxmap__store_u32_param(auxmap, open_modes_to_scap(flags, mode));

	/* Parameter 6: dev (type: PT_UINT32) */
	auxmap__store_u32_param(auxmap, dev);

	/* Parameter 7: ino (type: PT_UINT64) */
	auxmap__store_u64_param(auxmap, ino);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/

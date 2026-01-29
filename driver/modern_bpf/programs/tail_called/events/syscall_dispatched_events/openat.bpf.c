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

	/* Parameter 8: dirfdpath (type: PT_FSPATH) - kernel-resolved dirfd path */
	if(dirfd == PPM_AT_FDCWD) {
		/* For AT_FDCWD, capture the process's current working directory
		 * in kernel space to prevent race conditions. This captures the
		 * actual CWD path at syscall time, before the process may exec
		 * or change directories.
		 */
		struct task_struct *task = get_current_task();
		struct fs_struct *fs = NULL;
		struct path cwd_path = {};

		BPF_CORE_READ_INTO(&fs, task, fs);
		if(fs != NULL) {
			BPF_CORE_READ_INTO(&cwd_path, fs, pwd);
			auxmap__store_d_path_approx(auxmap, &cwd_path);
		} else {
			/* If we cannot access fs_struct, store empty and fall back
			 * to user space resolution.
			 */
			auxmap__store_empty_param(auxmap);
		}
	} else if(dirfd >= 0) {
		/* Resolve the dirfd path in kernel space to prevent race conditions.
		 * This captures the actual directory path at syscall time, before
		 * the process may exec or the FD table may change.
		 */
		struct file *dir_file = extract__file_struct_from_fd(dirfd);
		if(dir_file != NULL) {
			struct path dir_path = {};
			BPF_CORE_READ_INTO(&dir_path, dir_file, f_path);
			auxmap__store_d_path_approx(auxmap, &dir_path);
		} else {
			/* If we cannot resolve the FD (e.g., it was closed between
			 * syscall entry and exit), store empty and fall back to
			 * user space resolution.
			 */
			auxmap__store_empty_param(auxmap);
		}
	} else {
		/* Invalid FD, store empty */
		auxmap__store_empty_param(auxmap);
	}

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/

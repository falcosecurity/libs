// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>
#include <helpers/interfaces/variable_size_event.h>

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(open_by_handle_at_e, struct pt_regs *regs, long id) {
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf,
	                           ctx,
	                           OPEN_BY_HANDLE_AT_E_SIZE,
	                           PPME_SYSCALL_OPEN_BY_HANDLE_AT_E)) {
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	// Here we have no parameters to collect.

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(open_by_handle_at_x, struct pt_regs *regs, long ret) {
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap) {
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SYSCALL_OPEN_BY_HANDLE_AT_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: ret (type: PT_FD) */
	auxmap__store_s64_param(auxmap, ret);

	/* Parameter 2: mountfd (type: PT_FD) */
	int32_t mountfd = (int32_t)extract__syscall_argument(regs, 0);
	if(mountfd == AT_FDCWD) {
		mountfd = PPM_AT_FDCWD;
	}
	auxmap__store_s64_param(auxmap, (int64_t)mountfd);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	bpf_tail_call(ctx, &extra_event_prog_tail_table, T1_OPEN_BY_HANDLE_AT_X);
	return 0;
}

SEC("tp_btf/sys_exit")
int BPF_PROG(t1_open_by_handle_at_x, struct pt_regs *regs, long ret) {
	dev_t dev = 0;
	uint64_t ino = 0;
	enum ppm_overlay ol = PPM_NOT_OVERLAY_FS;

	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap) {
		return 0;
	}

	/*=============================== COLLECT PARAMETERS  ===========================*/

	uint32_t flags = (uint32_t)extract__syscall_argument(regs, 2);
	flags = (uint32_t)open_flags_to_scap(flags);
	/* We collect dev, ino and overlay from the file descriptor only if it is valid */
	if(ret > 0) {
		extract__dev_ino_overlay_from_fd(ret, &dev, &ino, &ol);

		/* Parameter 3: flags (type: PT_FLAGS32) */
		/* update flags if file is created */
		flags |= extract__fmode_created_from_fd(ret);
		if(ol == PPM_OVERLAY_UPPER) {
			flags |= PPM_FD_UPPER_LAYER;
		} else if(ol == PPM_OVERLAY_LOWER) {
			flags |= PPM_FD_LOWER_LAYER;
		}
	}
	auxmap__store_u32_param(auxmap, flags);

	/* We collect the file path from the file descriptor only if it is valid */
	if(ret > 0) {
		/* Parameter 4: path (type: PT_FSPATH) */
		struct file *f = extract__file_struct_from_fd(ret);
		if(f != NULL) {
			auxmap__store_d_path_approx(auxmap, &(f->f_path));
		} else {
			auxmap__store_empty_param(auxmap);
		}
	} else {
		auxmap__store_empty_param(auxmap);
	}

	/* Parameter 5: dev (type: PT_UINT32) */
	auxmap__store_u32_param(auxmap, dev);

	/* Parameter 6: ino (type: PT_UINT64) */
	auxmap__store_u64_param(auxmap, ino);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap, ctx);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/

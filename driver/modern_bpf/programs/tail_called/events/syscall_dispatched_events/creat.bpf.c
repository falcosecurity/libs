// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/variable_size_event.h>

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(creat_e, struct pt_regs *regs, long id) {
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap) {
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SYSCALL_CREAT_E);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: name (type: PT_FSPATH) */
	unsigned long name_pointer = extract__syscall_argument(regs, 0);
	auxmap__store_charbuf_param(auxmap, name_pointer, MAX_PATH, USER);

	/* Parameter 2: mode (type: PT_UINT32) */
	unsigned long mode = extract__syscall_argument(regs, 1);
	auxmap__store_u32_param(auxmap, open_modes_to_scap(O_CREAT, mode));

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(creat_x, struct pt_regs *regs, long ret) {
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap) {
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SYSCALL_CREAT_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: fd (type: PT_FD) */
	auxmap__store_s64_param(auxmap, ret);

	/* Parameter 2: name (type: PT_FSPATH) */
	unsigned long name_pointer = extract__syscall_argument(regs, 0);
	auxmap__store_charbuf_param(auxmap, name_pointer, MAX_PATH, USER);

	/* Parameter 3: mode (type: PT_UINT32) */
	unsigned long mode = extract__syscall_argument(regs, 1);
	auxmap__store_u32_param(auxmap, open_modes_to_scap(O_CREAT, mode));

	dev_t dev = 0;
	uint64_t ino = 0;
	enum ppm_overlay ol = PPM_NOT_OVERLAY_FS;
	uint16_t creat_flags = 0;

	if(ret > 0) {
		extract__dev_ino_overlay_from_fd(ret, &dev, &ino, &ol);
	}

	/* Parameter 4: dev (type: PT_UINT32) */
	auxmap__store_u32_param(auxmap, dev);

	/* Parameter 5: ino (type: PT_UINT64) */
	auxmap__store_u64_param(auxmap, ino);

	/* Parameter 6: creat_flags (type: PT_FLAGS16) */
	if(ol == PPM_OVERLAY_UPPER) {
		creat_flags |= PPM_FD_UPPER_LAYER_CREAT;
	} else if(ol == PPM_OVERLAY_LOWER) {
		creat_flags |= PPM_FD_LOWER_LAYER_CREAT;
	}
	auxmap__store_u16_param(auxmap, creat_flags);
	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/

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
int BPF_PROG(mknodat_e,
	     struct pt_regs *regs,
	     long id)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, MKNODAT_E_SIZE, PPME_SYSCALL_MKNODAT_E))
	{
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
int BPF_PROG(mknodat_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SYSCALL_MKNODAT_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: ret (type: PT_ERRNO) */
	auxmap__store_s64_param(auxmap, ret);

	/* Parameter 2: dirfd (type: PT_FD) */
	int32_t dirfd = (int32_t)extract__syscall_argument(regs, 0);
	if(dirfd == AT_FDCWD)
	{
		dirfd = PPM_AT_FDCWD;
	}
	auxmap__store_s64_param(auxmap, (int64_t)dirfd);

	/* Parameter 2: path (type: PT_CHARBUF) */
	unsigned long path_pointer = extract__syscall_argument(regs, 1);
	auxmap__store_charbuf_param(auxmap, path_pointer, MAX_PATH, USER);

	/* Parameter 3: mode (type: PT_MODE) */
	uint32_t mode = (uint32_t)extract__syscall_argument(regs, 2);
	auxmap__store_u32_param(auxmap, mknod_mode_to_scap(mode));

	/* Parameter 4: dev (type: PT_UINT32) */
	uint32_t dev = (uint32_t)extract__syscall_argument(regs, 3);
	auxmap__store_u32_param(auxmap, encode_dev(dev));


	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap, ctx);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/

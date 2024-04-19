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
int BPF_PROG(renameat2_e,
	     struct pt_regs *regs,
	     long id)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, RENAMEAT2_E_SIZE, PPME_SYSCALL_RENAMEAT2_E))
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
int BPF_PROG(renameat2_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SYSCALL_RENAMEAT2_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	auxmap__store_s64_param(auxmap, ret);

	/* Parameter 2: olddirfd (type: PT_FD) */
	int32_t olddirfd = (int32_t)extract__syscall_argument(regs, 0);
	if(olddirfd == AT_FDCWD)
	{
		olddirfd = PPM_AT_FDCWD;
	}
	auxmap__store_s64_param(auxmap, (int64_t)olddirfd);

	/* Parameter 3: oldpath (type: PT_FSRELPATH) */
	unsigned long old_path_pointer = extract__syscall_argument(regs, 1);
	auxmap__store_charbuf_param(auxmap, old_path_pointer, MAX_PATH, USER);

	/* Parameter 4: newdirfd (type: PT_FD) */
	int32_t newdirfd = (int32_t)extract__syscall_argument(regs, 2);
	if(newdirfd == AT_FDCWD)
	{
		newdirfd = PPM_AT_FDCWD;
	}
	auxmap__store_s64_param(auxmap, (int64_t)newdirfd);

	/* Parameter 5: newpath (type: PT_FSRELPATH) */
	unsigned long new_path_pointer = extract__syscall_argument(regs, 3);
	auxmap__store_charbuf_param(auxmap, new_path_pointer, MAX_PATH, USER);

	/* Parameter 6: flags (type: PT_FLAGS32) */
	uint32_t flags = (uint32_t)extract__syscall_argument(regs, 4);
	/// TODO: we have to create an helper method to convert these flags to the scap format.
	auxmap__store_u32_param(auxmap, flags);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap, ctx);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/

/*
 * Copyright (C) 2022 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>
#include <helpers/interfaces/variable_size_event.h>

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(access_e,
	     struct pt_regs *regs,
	     long id)
{
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SYSCALL_ACCESS_E);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: mode (type: PT_UINT32) */
	unsigned long mode = (u32)extract__syscall_argument(regs, 1);
	auxmap__store_u32_param(auxmap, (u32)access_flags_to_scap(mode));

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__submit_event(auxmap);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/


/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(access_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SYSCALL_ACCESS_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

        /* Parameter 1: res (type: PT_ERRNO) */
        auxmap__store_s64_param(auxmap, ret);

	/* Parameter 2: pathname (type: PT_FSPATH) */
	unsigned long mode = (u32)extract__syscall_argument(regs, 1);
	auxmap__store_u32_param(auxmap, (u32)access_flags_to_scap(mode));

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__submit_event(auxmap);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/


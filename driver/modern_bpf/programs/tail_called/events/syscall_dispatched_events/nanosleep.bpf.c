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
int BPF_PROG(nanosleep_e,
	     struct pt_regs *regs,
	     long id)
{
        struct auxiliary_map *auxmap = auxmap__get();
        if(!auxmap)
        {
                return 0;
        }

        auxmap__preload_event_header(auxmap, PPME_SYSCALL_NANOSLEEP_E);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: interval (type: PT_RELTIME) */
        struct __kernel_timespec ts = {0};
        unsigned long ts_pointer = extract__syscall_argument(regs, 0);
        if(bpf_probe_read_user(&ts, bpf_core_type_size(struct __kernel_timespec), (void *)ts_pointer))
        {
                /* In case of invalid pointer, like in the other drivers */
                auxmap__store_u64_param(auxmap, (u64)-1);
        }
        else
        {
                auxmap__store_u64_param(auxmap, ((u64)ts.tv_sec) * 1000000000 + ts.tv_nsec);
        }

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(nanosleep_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SYSCALL_NANOSLEEP_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	auxmap__store_s64_param(auxmap, ret);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/

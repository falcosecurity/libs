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
int BPF_PROG(memfd_create_e,
         struct pt_regs *regs,
         long id)
{
    struct ringbuf_struct ringbuf;
    if(!ringbuf__reserve_space(&ringbuf, ctx, MEMFD_CREATE_E_SIZE, PPME_SYSCALL_MEMFD_CREATE_E))
    {
        return 0;
    }
    
    ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(memfd_create_x,
         struct pt_regs *regs,
         long ret)
{
    struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

    auxmap__preload_event_header(auxmap, PPME_SYSCALL_MEMFD_CREATE_X);

    /*=============================== COLLECT PARAMETERS  ===========================*/

    /* Parameter 1: ret (type: PT_FD) */
    auxmap__store_s64_param(auxmap, ret);

    /* Parameter 2: file name (type: PT_CHARBUF)  */
    unsigned long name_pointer = extract__syscall_argument(regs, 0);
    auxmap__store_charbuf_param(auxmap, name_pointer, MAX_PATH, USER);

    /* Parameter 3: flags (type: PT_FLAGS32) */
    u32 flags = (u32)extract__syscall_argument(regs, 1);
    auxmap__store_u32_param(auxmap, memfd_create_flags_to_scap(flags));
    /*=============================== COLLECT PARAMETERS  ===========================*/

    auxmap__finalize_event_header(auxmap);

    auxmap__submit_event(auxmap, ctx);

    return 0;
}

/*=============================== EXIT EVENT ===========================*/
/*
 * Copyright (C) 2022 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/variable_size_event.h>
/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(pidfd_getfd_e,
         struct pt_regs *regs,
         long id)
{
    struct auxiliary_map *auxmap = auxmap__get();
    if(!auxmap)
	{
		return 0;
	}

    auxmap__preload_event_header(auxmap, PPME_SYSCALL_PIDFD_GETFD_E);

	/*=============================== COLLECT PARAMETERS  ===========================*/


	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

    auxmap__submit_event(auxmap, ctx);

    return 0;
}




/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")

int BPF_PROG(pidfd_getfd_x,
         struct pt_regs *regs,
         long ret)

{   
    struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

    auxmap__preload_event_header(auxmap, PPME_SYSCALL_PIDFD_GETFD_X);


    /*=============================== COLLECT PARAMETERS  ===========================*/

    /* Parameter 1: ret (type: PT_FD) */
    auxmap__store_s64_param(auxmap, ret);

    /* Parameter 2: pidfd (type: PT_FD) */
    s64 pidfd = (s64)extract__syscall_argument(regs, 0);
    auxmap__store_s64_param(auxmap, pidfd);

    /* Parameter 3: targetfd (type: PT_FD) */
    s64 targetfd = (s64)extract__syscall_argument(regs, 1);
    auxmap__store_s64_param(auxmap, pidfd);

    /* Parameter 4: flags (type: PT_FLAGS32) 

     The flags argument is reserved for future use.  Currently, it must be specified as 0.
     See https://elixir.bootlin.com/linux/latest/source/kernel/pid.c#L709
     
    */
    u32 flags = 0;
    auxmap__store_u32_param(auxmap, flags);

    /*=============================== COLLECT PARAMETERS  ===========================*/

    auxmap__finalize_event_header(auxmap);

    auxmap__submit_event(auxmap, ctx);
    return 0;

}

/*=============================== EXIT EVENT ===========================*/
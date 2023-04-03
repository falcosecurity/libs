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
int BPF_PROG(prctl_e,
	     struct pt_regs *regs,
	     long id)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, PRCTL_E_SIZE))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf, PPME_SYSCALL_PRCTL_E);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	// Here we have no parameters to collect.

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;


}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(prctl_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SYSCALL_PRCTL_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	auxmap__store_s64_param(auxmap, ret);

	/* Parameter 2: option (type: PT_UINT64) */
	u64 option = (u64)extract__syscall_argument(regs, 0);
	auxmap__store_u64_param(auxmap, option);

	/* Parameter 3: arg2 (type: PT_CHARBUF) */
	unsigned long arg2 = extract__syscall_argument(regs, 1);
	auxmap__store_u64_param(auxmap, arg2);

	/* Parameter 4: arg3 (type: PT_UINT64) */
	unsigned long arg3 = extract__syscall_argument(regs, 2);
	auxmap__store_u64_param(auxmap, arg3);

	/* Parameter 5: arg4 (type: PT_UINT64) */
	unsigned long arg4 = extract__syscall_argument(regs, 3);
	auxmap__store_u64_param(auxmap, arg4);

	/* Parameter 6: arg5 (type: PT_UINT64) */
	unsigned long arg5 = extract__syscall_argument(regs, 4);
	auxmap__store_u64_param(auxmap, arg5);

	/* Parameter 7: arg2str (type: PT_CHARBUF) */
	if(option == 15){
		auxmap__store_charbuf_param(auxmap, arg2, MAX_PATH, USER);
	}else{
		auxmap__store_charbuf_param(auxmap, 0, MAX_PATH, USER);
	}

	/* Parameter 8: arg2int (type: PT_UINT64) */
	if(option == 37){
		u64 reaper_pid;
		bpf_probe_read_user(&reaper_pid, sizeof(reaper_pid), (void*)arg2);
		auxmap__store_u64_param(auxmap, (int)reaper_pid);
	}else if(option == 15){
		auxmap__store_u64_param(auxmap, 0);
	}else{
		auxmap__store_u64_param(auxmap, arg2);
	}


	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/

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
int BPF_PROG(open_by_handle_at_e,
	     struct pt_regs *regs,
	     long id)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, OPEN_BY_HANDLE_AT_E_SIZE, PPME_SYSCALL_OPEN_BY_HANDLE_AT_E))
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
int BPF_PROG(open_by_handle_at_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SYSCALL_OPEN_BY_HANDLE_AT_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: ret (type: PT_FD) */
	auxmap__store_s64_param(auxmap, ret);

	/* Parameter 2: mountfd (type: PT_FD) */
	s32 mountfd = (s32)extract__syscall_argument(regs, 0);
	if(mountfd == AT_FDCWD)
	{
		mountfd = PPM_AT_FDCWD;
	}
	auxmap__store_s64_param(auxmap, (s64)mountfd);

	/* Parameter 3: flags (type: PT_FLAGS32) */
	u32 flags = (u32)extract__syscall_argument(regs, 2);
	flags = (u32)open_flags_to_scap(flags);
	/* update flags if file is created */
	flags |= extract__fmode_created_from_fd(ret);

	auxmap__store_u32_param(auxmap, flags);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	bpf_tail_call(ctx, &extra_event_prog_tail_table, T1_OPEN_BY_HANDLE_AT_X);
	return 0;
}

SEC("tp_btf/sys_exit")
int BPF_PROG(t1_open_by_handle_at_x, struct pt_regs *regs, long ret)
{
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 4: path (type: PT_FSPATH) */
	/* We collect the file path from the file descriptor only if it is valid */
	if(ret > 0)
	{
		struct file *f = extract__file_struct_from_fd(ret);
		if(f != NULL)
		{
			auxmap__store_d_path_approx(auxmap, &(f->f_path));
		}
		else
		{
			auxmap__store_empty_param(auxmap);
		}
	}
	else
	{
		auxmap__store_empty_param(auxmap);
	}

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap, ctx);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/

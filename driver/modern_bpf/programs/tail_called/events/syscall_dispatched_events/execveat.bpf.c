/*
 * Copyright (C) 2022 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/variable_size_event.h>

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(execveat_e,
	     struct pt_regs *regs,
	     long id)
{
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}
	auxmap__preload_event_header(auxmap, PPME_SYSCALL_EXECVEAT_E);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: dirfd (type: PT_FD) */
	s32 dirfd = (s32)extract__syscall_argument(regs, 0);
	if(dirfd == AT_FDCWD)
	{
		dirfd = PPM_AT_FDCWD;
	}
	auxmap__store_s64_param(auxmap, (s64)dirfd);

	/* Parameter 2: pathname (type: PT_FSRELPATH) */
	unsigned long pathname_pointer = extract__syscall_argument(regs, 1);
	auxmap__store_charbuf_param(auxmap, pathname_pointer, USER);

	/* Parameter 3: flags (type: PT_FLAGS32) */
	unsigned long flags = extract__syscall_argument(regs, 4);
	auxmap__store_u32_param(auxmap, execveat_flags_to_scap(flags));

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);
	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(execveat_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}
	auxmap__preload_event_header(auxmap, PPME_SYSCALL_EXECVEAT_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	auxmap__store_s64_param(auxmap, ret);

	struct task_struct *task = get_current_task();

	/* This is a charbuf pointer array.
	 * Every element of `argv` array is a pointer to a charbuf.
	 * Here the first pointer points to `exe` param while all
	 * the others point to the different args.
	 *
	 * Please note: this bpf program is called only if the `execveat` fails
	 * so we cannot get arguments from the kernel memory.
	 */
	unsigned long argv = extract__syscall_argument(regs, 2);

	/* Parameter 2: exe (type: PT_CHARBUF) */
	auxmap__store_single_charbuf_param_from_array(auxmap, argv, 0, USER);

	/* Parameter 3: args (type: PT_CHARBUFARRAY) */
	auxmap__store_multiple_charbufs_param_from_array(auxmap, argv, 1, USER);

	/* Parameter 4: tid (type: PT_PID) */
	/* this is called `tid` but it is the `pid`. */
	s64 pid = (s64)extract__task_xid_nr(task, PIDTYPE_PID);
	auxmap__store_s64_param(auxmap, pid);

	/* Parameter 5: pid (type: PT_PID) */
	/* this is called `pid` but it is the `tgid`. */
	s64 tgid = (s64)extract__task_xid_nr(task, PIDTYPE_TGID);
	auxmap__store_s64_param(auxmap, tgid);

	/* Parameter 6: ptid (type: PT_PID) */
	/* this is called `ptid` but it is the `pgid`. */
	s64 pgid = (s64)extract__task_xid_nr(task, PIDTYPE_PGID);
	auxmap__store_s64_param(auxmap, pgid);

	/* Parameter 7: cwd (type: PT_CHARBUF) */
	/// TODO: right now we leave the current working directory empty like in the old probe.
	auxmap__store_empty_param(auxmap);

	/* Parameter 8: fdlimit (type: PT_UINT64) */
	unsigned long fdlimit = 0;
	extract__fdlimit(task, &fdlimit);
	auxmap__store_u64_param(auxmap, fdlimit);

	/* Parameter 9: pgft_maj (type: PT_UINT64) */
	unsigned long pgft_maj = 0;
	extract__pgft_maj(task, &pgft_maj);
	auxmap__store_u64_param(auxmap, pgft_maj);

	/* Parameter 10: pgft_min (type: PT_UINT64) */
	unsigned long pgft_min = 0;
	extract__pgft_min(task, &pgft_min);
	auxmap__store_u64_param(auxmap, pgft_min);

	struct mm_struct *mm = NULL;
	READ_TASK_FIELD_INTO(&mm, task, mm);

	/* Parameter 11: vm_size (type: PT_UINT32) */
	u32 vm_size = extract__vm_size(mm);
	auxmap__store_u32_param(auxmap, vm_size);

	/* Parameter 12: vm_rss (type: PT_UINT32) */
	u32 vm_rss = extract__vm_rss(mm);
	auxmap__store_u32_param(auxmap, vm_rss);

	/* Parameter 13: vm_swap (type: PT_UINT32) */
	u32 vm_swap = extract__vm_swap(mm);
	auxmap__store_u32_param(auxmap, vm_swap);

	/* Parameter 14: comm (type: PT_CHARBUF) */
	auxmap__store_charbuf_param(auxmap, (unsigned long)task->comm, KERNEL);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* We have to split here the bpf program, otherwise it is too large
	 * for the verifier (limit 1000000 instructions).
	 */
	bpf_tail_call(ctx, &extra_event_prog_tail_table, T1_EXECVEAT_X);
	return 0;
}

SEC("tp_btf/sys_exit")
int BPF_PROG(t1_execveat_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

	/*=============================== COLLECT PARAMETERS  ===========================*/

	struct task_struct *task = get_current_task();

	/* Parameter 15: cgroups (type: PT_CHARBUFARRAY) */
	auxmap__store_cgroups_param(auxmap, task);

	/* Parameter 16: env (type: PT_CHARBUFARRAY) */
	unsigned long envp = extract__syscall_argument(regs, 3);
	auxmap__store_multiple_charbufs_param_from_array(auxmap, envp, 0, USER);

	/* Parameter 17: tty (type: PT_INT32) */
	u32 tty = exctract__tty(task);
	auxmap__store_s32_param(auxmap, (s32)tty);

	/* Parameter 18: pgid (type: PT_PID) */
	pid_t pgid = extract__task_xid_vnr(task, PIDTYPE_PGID);
	auxmap__store_s64_param(auxmap, (s64)pgid);

	/* Parameter 19: loginuid (type: PT_INT32) */
	u32 loginuid;
	extract__loginuid(task, &loginuid);
	auxmap__store_s32_param(auxmap, (s32)loginuid);

	/* Parameter 20: flags (type: PT_FLAGS32) */
	/// TODO: we still have to manage `exe_writable` flag.
	u32 flags = 0;
	auxmap__store_u32_param(auxmap, flags);

	/* Parameter 21: cap_inheritable (type: PT_UINT64) */
	u64 cap_inheritable = extract__capability(task, CAP_INHERITABLE);
	auxmap__store_u64_param(auxmap, cap_inheritable);

	/* Parameter 22: cap_permitted (type: PT_UINT64) */
	u64 cap_permitted = extract__capability(task, CAP_PERMITTED);
	auxmap__store_u64_param(auxmap, cap_permitted);

	/* Parameter 23: cap_effective (type: PT_UINT64) */
	u64 cap_effective = extract__capability(task, CAP_EFFECTIVE);
	auxmap__store_u64_param(auxmap, cap_effective);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);
	return 0;
}

/*=============================== EXIT EVENT ===========================*/

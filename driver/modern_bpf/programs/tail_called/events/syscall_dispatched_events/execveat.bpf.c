// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/variable_size_event.h>

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(execveat_x, struct pt_regs *regs, long ret) {
	/*
	 * The only purpose of this program is to catch `execveat` events in case of system call
	 * failure. In case of system call success, `execveat` events are caught by our tracepoint
	 * program on `sched/sched_process_exec` (see comment on `sched_p_exec` in
	 * `driver/modern_bpf/programs/attached/events/sched_process_exec.bpf.c`). A successful
	 * `execveat` call is identified by `ret == 0`.
	 */
	if(ret == 0) {
		return 0;
	}

	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap) {
		return 0;
	}
	auxmap__preload_event_header(auxmap, PPME_SYSCALL_EXECVEAT_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	auxmap__store_s64_param(auxmap, ret);

	/* Keep the heavy args loop in the entry program so tail-called stages
	 * don't combine tail calls with bpf-to-bpf helper calls on old kernels.
	 */
	unsigned long argv = extract__syscall_argument(regs, 2);

	/* Parameter 2: exe (type: PT_CHARBUF) */
	/* Parameter 3: args (type: PT_CHARBUFARRAY) */
	auxmap__store_exe_args_failure(auxmap, (char **)argv);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	bpf_tail_call(ctx, &syscall_exit_extra_tail_table, T1_EXECVEAT_X);
	return 0;
}

SEC("tp_btf/sys_exit")
int BPF_PROG(t1_execveat_x, struct pt_regs *regs, long ret) {
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap) {
		return 0;
	}

	/*=============================== COLLECT PARAMETERS  ===========================*/

	struct task_struct *task = get_current_task();

	/* Parameter 4: tid (type: PT_PID) */
	/* this is called `tid` but it is the `pid`. */
	int64_t pid = (int64_t)extract__task_xid_nr(task, PIDTYPE_PID);
	auxmap__store_s64_param(auxmap, pid);

	/* Parameter 5: pid (type: PT_PID) */
	/* this is called `pid` but it is the `tgid`. */
	int64_t tgid = (int64_t)extract__task_xid_nr(task, PIDTYPE_TGID);
	auxmap__store_s64_param(auxmap, tgid);

	/* Parameter 6: ptid (type: PT_PID) */
	pid_t ppid = extract__task_ppid_nr(task);
	auxmap__store_s64_param(auxmap, (int64_t)ppid);

	/* Parameter 7: cwd (type: PT_CHARBUF) */
	/// TODO: right now we leave the current working directory empty like in the old probe.
	auxmap__store_empty_param(auxmap);

	/* Parameter 8: fdlimit (type: PT_UINT64) */
	unsigned long fdlimit = extract__fdlimit(task);
	auxmap__store_u64_param(auxmap, fdlimit);

	/* Parameter 9: pgft_maj (type: PT_UINT64) */
	unsigned long pgft_maj = extract__pgft_maj(task);
	auxmap__store_u64_param(auxmap, pgft_maj);

	/* Parameter 10: pgft_min (type: PT_UINT64) */
	unsigned long pgft_min = extract__pgft_min(task);
	auxmap__store_u64_param(auxmap, pgft_min);

	struct mm_struct *mm = NULL;
	READ_TASK_FIELD_INTO(&mm, task, mm);

	/* Parameter 11: vm_size (type: PT_UINT32) */
	uint32_t vm_size = extract__vm_size(mm);
	auxmap__store_u32_param(auxmap, vm_size);

	/* Parameter 12: vm_rss (type: PT_UINT32) */
	uint32_t vm_rss = extract__vm_rss(mm);
	auxmap__store_u32_param(auxmap, vm_rss);

	/* Parameter 13: vm_swap (type: PT_UINT32) */
	uint32_t vm_swap = extract__vm_swap(mm);
	auxmap__store_u32_param(auxmap, vm_swap);

	/* Parameter 14: comm (type: PT_CHARBUF) */
	auxmap__store_charbuf_param(auxmap, (unsigned long)task->comm, TASK_COMM_LEN, KERNEL);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	bpf_tail_call(ctx, &syscall_exit_extra_tail_table, T2_EXECVEAT_X);
	return 0;
}

SEC("tp_btf/sys_exit")
int BPF_PROG(t2_execveat_x, struct pt_regs *regs, long ret) {
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap) {
		return 0;
	}

	/*=============================== COLLECT PARAMETERS  ===========================*/

	struct task_struct *task = get_current_task();

	/* Parameter 15: cgroups (type: PT_CHARBUFARRAY) */
	auxmap__store_cgroups_param(auxmap, task);

	/* Parameter 16: env (type: PT_CHARBUFARRAY) */
	unsigned long envp = extract__syscall_argument(regs, 3);
	auxmap__store_env_failure(auxmap, (char **)envp);

	/* Parameter 17: tty (type: PT_UID) */
	uint32_t tty = extract__tty(task);
	auxmap__store_u32_param(auxmap, tty);

	/* Parameter 18: pgid (type: PT_PID) */
	pid_t pgid = extract__task_xid_vnr(task, PIDTYPE_PGID);
	auxmap__store_s64_param(auxmap, (int64_t)pgid);

	/* Parameter 19: loginuid (type: PT_UID) */
	uint32_t loginuid = extract__loginuid(task);
	auxmap__store_u32_param(auxmap, loginuid);

	/* Parameter 20: flags (type: PT_FLAGS32) */
	uint32_t flags = 0;
	struct inode *exe_inode = extract__exe_inode_from_task(task);
	struct file *exe_file = extract__exe_file_from_task(task);

	if(extract__exe_writable(task, exe_inode)) {
		flags |= PPM_EXE_WRITABLE;
	}
	enum ppm_overlay overlay = extract__overlay_layer(exe_file);
	if(overlay == PPM_OVERLAY_UPPER) {
		flags |= PPM_EXE_UPPER_LAYER;
	} else if(overlay == PPM_OVERLAY_LOWER) {
		flags |= PPM_EXE_LOWER_LAYER;
	}
	if(extract__exe_from_memfd(exe_file)) {
		flags |= PPM_EXE_FROM_MEMFD;
	}
	auxmap__store_u32_param(auxmap, flags);

	/* Parameter 21: cap_inheritable (type: PT_UINT64) */
	uint64_t cap_inheritable = extract__capability(task, CAP_INHERITABLE);
	auxmap__store_u64_param(auxmap, cap_inheritable);

	/* Parameter 22: cap_permitted (type: PT_UINT64) */
	uint64_t cap_permitted = extract__capability(task, CAP_PERMITTED);
	auxmap__store_u64_param(auxmap, cap_permitted);

	/* Parameter 23: cap_effective (type: PT_UINT64) */
	uint64_t cap_effective = extract__capability(task, CAP_EFFECTIVE);
	auxmap__store_u64_param(auxmap, cap_effective);

	/* Parameter 24: exe_file ino (type: PT_UINT64) */
	uint64_t ino = extract__ino_from_inode(exe_inode);
	auxmap__store_u64_param(auxmap, ino);

	/* Parameter 25: exe_file ctime (last status change time, epoch value in nanoseconds) (type:
	 * PT_ABSTIME) */
	struct timespec64 time = {0, 0};
	extract__ctime_from_inode(exe_inode, &time);
	auxmap__store_u64_param(auxmap, extract__epoch_ns_from_time(time));

	/* Parameter 26: exe_file mtime (last modification time, epoch value in nanoseconds) (type:
	 * PT_ABSTIME) */
	extract__mtime_from_inode(exe_inode, &time);
	auxmap__store_u64_param(auxmap, extract__epoch_ns_from_time(time));

	/* Parameter 27: euid (type: PT_UID) */
	uint32_t euid = extract__euid(task);
	auxmap__store_u32_param(auxmap, euid);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	bpf_tail_call(ctx, &syscall_exit_extra_tail_table, T3_EXECVEAT_X);
	return 0;
}

SEC("tp_btf/sys_exit")
int BPF_PROG(t3_execveat_x, struct pt_regs *regs, long ret) {
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap) {
		return 0;
	}

	/*=============================== COLLECT PARAMETERS  ===========================*/

	struct task_struct *task = get_current_task();

	/* Parameter 28: trusted_exepath (type: PT_FSPATH) */
	auxmap__store_task_exe_file_path(auxmap, task);

	/* Parameter 29: pgid (type: PT_PID) */
	pid_t pgid = extract__task_xid_nr(task, PIDTYPE_PGID);
	auxmap__store_s64_param(auxmap, (int64_t)pgid);

	/* Parameter 30: egid (type: PT_GID) */
	uint32_t egid = extract__egid(task);
	auxmap__store_u32_param(auxmap, egid);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);
	return 0;
}

/*=============================== EXIT EVENT ===========================*/

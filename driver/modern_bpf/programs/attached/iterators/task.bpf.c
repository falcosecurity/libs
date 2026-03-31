// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2026 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/variable_size_event.h>

SEC("iter.s/task")
int dump_task(struct bpf_iter__task *ctx) {
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;

	if(!task) {
		return 0;
	}

	uint32_t task_flags = READ_TASK_FIELD(task, flags);

	/* We are not interested in kernel threads. */
	if(task_flags & PF_KTHREAD) {
		return 0;
	}

	pid_t tgid = extract__task_xid_nr(task, PIDTYPE_TGID);
	pid_t pid = extract__task_xid_nr(task, PIDTYPE_PID);
	uint64_t tgid_pid = (uint64_t)tgid << 32 | (uint64_t)pid;

	struct auxiliary_map *auxmap = auxmap_iter__get();
	if(!auxmap) {
		return 0;
	}

	auxmap_iter__preload_event_header(auxmap, tgid_pid, PPME_ITER_TASK_E);

	/* Parameter 1: ppid (type: PT_PID32) */
	pid_t ppid = extract__task_ppid_nr(task);
	auxmap__store_s32_param(auxmap, (int32_t)ppid);

	/* Parameter 2: pgid (type: PT_PID32) */
	pid_t pgid = extract__task_xid_nr(task, PIDTYPE_PGID);
	auxmap__store_s32_param(auxmap, (int32_t)pgid);

	/* Parameter 3: vpgid (type: PT_PID32) */
	pid_t vpgid = extract__task_xid_vnr(task, PIDTYPE_PGID);
	auxmap__store_s32_param(auxmap, (int32_t)vpgid);

	/* Parameter 4: sid (type: PT_PID32) */
	pid_t sid = extract__task_xid_nr(task, PIDTYPE_SID);
	auxmap__store_s32_param(auxmap, (int32_t)sid);

	/* Parameter 5: comm (type: PT_CHARBUF) */
	auxmap__store_charbuf_param(auxmap, (unsigned long)task->comm, TASK_COMM_LEN, KERNEL);

	/* Parameter 6: argv (type: PT_CHARBUFARRAY) */
	unsigned long argv_start_pointer = READ_TASK_FIELD(task, mm, arg_start);
	unsigned long argv_end_pointer = READ_TASK_FIELD(task, mm, arg_end);
	unsigned long total_argv_len = argv_end_pointer - argv_start_pointer;
	auxmap__store_user_task_charbufarray_param(auxmap,
	                                           argv_start_pointer,
	                                           total_argv_len,
	                                           MAX_PROC_ARG_ENV,
	                                           task);

	/* Parameter 7: exepath (type: PT_FSPATH) */
	auxmap__store_task_exe_file_path_sleepable(auxmap, task);

	/* Parameter 8: flags (type: PT_FLAGS32) */
	uint32_t flags = 0;
	struct inode *exe_inode = extract__exe_inode_from_task(task);
	if(extract__exe_writable(task, exe_inode)) {
		flags |= PPM_EXE_WRITABLE;
	}
	struct file *exe_file = extract__exe_file_from_task(task);
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

	/* Parameter 9: env (type: PT_CHARBUFARRAY) */
	unsigned long env_start_pointer = READ_TASK_FIELD(task, mm, env_start);
	unsigned long env_end_pointer = READ_TASK_FIELD(task, mm, env_end);
	unsigned long total_env_len = env_end_pointer - env_start_pointer;
	auxmap__store_user_task_charbufarray_param(auxmap,
	                                           env_start_pointer,
	                                           total_env_len,
	                                           MAX_PROC_ARG_ENV,
	                                           task);

	/* Parameter 10: cwd (type: PT_CHARBUF) */
	auxmap__store_task_cwd_sleepable(auxmap, task);

	/* Parameter 11: fdlimit (type: PT_UINT64) */
	unsigned long fdlimit = extract__fdlimit(task);
	auxmap__store_u64_param(auxmap, (uint64_t)fdlimit);

	// TODO(ekoops): implement logic to reliably extract flags.

	/* Parameter 12: euid (type: PT_UID) */
	uint32_t euid = extract__euid(task);
	auxmap__store_u32_param(auxmap, euid);

	/* Parameter 13: egid (type: PT_GID) */
	uint32_t egid = extract__egid(task);
	auxmap__store_u32_param(auxmap, egid);

	/* Parameter 14: cap_permitted (type: PT_UINT64) */
	uint64_t cap_permitted = extract__capability(task, CAP_PERMITTED);
	auxmap__store_u64_param(auxmap, cap_permitted);

	/* Parameter 15: cap_effective (type: PT_UINT64) */
	uint64_t cap_effective = extract__capability(task, CAP_EFFECTIVE);
	auxmap__store_u64_param(auxmap, cap_effective);

	/* Parameter 16: cap_inheritable (type: PT_UINT64) */
	uint64_t cap_inheritable = extract__capability(task, CAP_INHERITABLE);
	auxmap__store_u64_param(auxmap, cap_inheritable);

	/* Parameter 17: exe_ino_num (type: PT_UINT64) */
	uint64_t ino = extract__ino_from_inode(exe_inode);
	auxmap__store_u64_param(auxmap, ino);

	/* Parameter 18: exe_ino_ctime (type: PT_ABSTIME) */
	struct timespec64 time = {0, 0};
	extract__ctime_from_inode(exe_inode, &time);
	auxmap__store_u64_param(auxmap, extract__epoch_ns_from_time(time));

	/* Parameter 19: exe_ino_mtime (type: PT_ABSTIME) */
	extract__mtime_from_inode(exe_inode, &time);
	auxmap__store_u64_param(auxmap, extract__epoch_ns_from_time(time));

	// warn: exe_ino_ctime_duration_clone_ts and exe_ino_ctime_duration_pidns_start are currently
	// set to zero in scap_procs.c (not explicitely, they are set to zero by memset) and so there's
	// no need to export from here.

	struct mm_struct *mm = NULL;
	READ_TASK_FIELD_INTO(&mm, task, mm);

	/* Parameter 20: vm_size (type: PT_UINT32) */
	uint32_t vm_size = extract__vm_size(mm);
	auxmap__store_u32_param(auxmap, vm_size);

	/* Parameter 21: vm_rss (type: PT_UINT32) */
	uint32_t vm_rss = extract__vm_rss(mm);
	auxmap__store_u32_param(auxmap, vm_rss);

	/* Parameter 22: vm_swap (type: PT_UINT32) */
	uint32_t vm_swap = extract__vm_swap(mm);
	auxmap__store_u32_param(auxmap, vm_swap);

	/* Parameter 23: pgft_maj (type: PT_UINT64) */
	unsigned long pgft_maj = extract__pgft_maj(task);
	auxmap__store_u64_param(auxmap, pgft_maj);

	/* Parameter 24: pgft_min (type: PT_UINT64) */
	unsigned long pgft_min = extract__pgft_min(task);
	auxmap__store_u64_param(auxmap, pgft_min);

	/* Parameter 25: vtgid (type: PT_PID32) */
	pid_t vtgid = extract__task_xid_vnr(task, PIDTYPE_TGID);
	auxmap__store_s32_param(auxmap, (int32_t)vtgid);

	/* Parameter 26: vpid (type: PT_PID32) */
	pid_t vpid = extract__task_xid_vnr(task, PIDTYPE_PID);
	auxmap__store_s32_param(auxmap, (int32_t)vpid);

	/* Parameter 27: pidns_init_start_ts (type: PT_UINT64) */
	uint64_t pidns_init_start_ts = extract__task_pidns_start_time(task, PIDTYPE_TGID, 0);
	auxmap__store_u64_param(auxmap, pidns_init_start_ts);

	/* Parameter 28: cgroups (type: PT_CHARBUFARRAY) */
	auxmap__store_cgroups_param(auxmap, task);

	/* Parameter 29: root (type: PT_FSPATH) */
	auxmap__store_task_root_sleepable(auxmap, task);

	// filterd_out and fdlist in scap_threadinfo are internal fields, not relevant in this context.

	/* Parameter 30: start_time (type: PT_ABSTIME) */
	uint64_t start_time = maps__get_boot_time() + READ_TASK_FIELD(task, start_boottime);
	auxmap__store_u64_param(auxmap, start_time);

	/* Parameter 31: tty (type: PT_UINT32) */
	uint32_t tty = extract__tty(task);
	auxmap__store_u32_param(auxmap, tty);

	/* Parameter 32: loginuid (type: PT_UID) */
	uint32_t loginuid = extract__loginuid(task);
	auxmap__store_u32_param(auxmap, loginuid);

	auxmap_iter__finalize_event_header(auxmap);
	return auxmap_iter__submit_event(auxmap, seq);
}

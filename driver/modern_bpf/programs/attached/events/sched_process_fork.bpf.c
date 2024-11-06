// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/variable_size_event.h>

/* From linux tree: /include/trace/events/sched.h
 * TP_PROTO(struct task_struct *parent,
 *      struct task_struct *child)
 */

#ifdef CAPTURE_SCHED_PROC_FORK

enum extra_sched_proc_fork_codes {
	T1_SCHED_PROC_FORK,
	T2_SCHED_PROC_FORK,
	// add more codes here.
	T_SCHED_PROC_FORK_MAX,
};

/*
 * FORWARD DECLARATIONS:
 * See the `BPF_PROG` macro in libbpf `libbpf/src/bpf_tracing.h`
 * #define BPF_PROG(name, args...)		\
 *    name(unsigned long long *ctx);	\
 */
int t1_sched_p_fork(unsigned long long *ctx);
int t2_sched_p_fork(unsigned long long *ctx);

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, T_SCHED_PROC_FORK_MAX);
	__uint(key_size, sizeof(__u32));
	__array(values, int(void *));
} extra_sched_proc_fork_calls SEC(".maps") = {
        .values =
                {
                        [T1_SCHED_PROC_FORK] = (void *)&t1_sched_p_fork,
                        [T2_SCHED_PROC_FORK] = (void *)&t2_sched_p_fork,
                        // add more tail calls here.
                },
};

/* chose a short name for bpftool debugging*/
SEC("tp_btf/sched_process_fork")
int BPF_PROG(sched_p_fork, struct task_struct *parent, struct task_struct *child) {
	struct task_struct *task = get_current_task();
	uint32_t flags = 0;
	READ_TASK_FIELD_INTO(&flags, task, flags);

	/* We are not interested in kernel threads. */
	if(flags & PF_KTHREAD) {
		return 0;
	}

	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap) {
		return 0;
	}
	auxmap__preload_event_header(auxmap, PPME_SYSCALL_CLONE_20_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* First of all we need to update the event header with the child tid.
	 * The clone child exit event must be generated by the child but while
	 * we are sending this event, we are still the parent so we have to
	 * modify the event header to simulate it.
	 */
	pid_t child_pid = 0;
	READ_TASK_FIELD_INTO(&child_pid, child, pid);
	struct ppm_evt_hdr *hdr = (struct ppm_evt_hdr *)auxmap->data;
	hdr->tid = (uint64_t)child_pid;

	/* Parameter 1: res (type: PT_ERRNO) */
	/* Please note: here we are in the clone child exit
	 * event, so the return value will be always 0.
	 */
	auxmap__store_s64_param(auxmap, 0);

	unsigned long arg_start_pointer = 0;
	unsigned long arg_end_pointer = 0;

	/* `arg_start` points to the memory area where arguments start.
	 * We directly read charbufs from there, not pointers to charbufs!
	 * We will store charbufs directly from memory.
	 */
	READ_TASK_FIELD_INTO(&arg_start_pointer, child, mm, arg_start);
	READ_TASK_FIELD_INTO(&arg_end_pointer, child, mm, arg_end);

	/* Parameter 2: exe (type: PT_CHARBUF) */
	/* We need to extract the len of `exe` arg so we can understand
	 * the overall length of the remaining args.
	 */
	uint16_t exe_arg_len =
	        auxmap__store_charbuf_param(auxmap, arg_start_pointer, MAX_PROC_EXE, USER);

	/* Parameter 3: args (type: PT_CHARBUFARRAY) */
	unsigned long total_args_len = arg_end_pointer - arg_start_pointer;
	auxmap__store_charbufarray_as_bytebuf(auxmap,
	                                      arg_start_pointer + exe_arg_len,
	                                      total_args_len - exe_arg_len,
	                                      MAX_PROC_ARG_ENV - exe_arg_len);

	/* Parameter 4: tid (type: PT_PID) */
	/* this is called `tid` but it is the `pid`. */
	int64_t pid = (int64_t)extract__task_xid_nr(child, PIDTYPE_PID);
	auxmap__store_s64_param(auxmap, pid);

	/* Parameter 5: pid (type: PT_PID) */
	/* this is called `pid` but it is the `tgid`. */
	int64_t tgid = (int64_t)extract__task_xid_nr(child, PIDTYPE_TGID);
	auxmap__store_s64_param(auxmap, tgid);

	/* Parameter 6: ptid (type: PT_PID) */
	/* this is called `ptid` but it is the `pgid`. */
	int64_t pgid = (int64_t)extract__task_xid_nr(child, PIDTYPE_PGID);
	auxmap__store_s64_param(auxmap, pgid);

	/* Parameter 7: cwd (type: PT_CHARBUF) */
	/// TODO: right now we leave the current working directory empty like in the old probe.
	auxmap__store_empty_param(auxmap);

	/* Parameter 8: fdlimit (type: PT_UINT64) */
	unsigned long fdlimit = 0;
	extract__fdlimit(child, &fdlimit);
	auxmap__store_u64_param(auxmap, fdlimit);

	/* Parameter 9: pgft_maj (type: PT_UINT64) */
	unsigned long pgft_maj = 0;
	extract__pgft_maj(child, &pgft_maj);
	auxmap__store_u64_param(auxmap, pgft_maj);

	/* Parameter 10: pgft_min (type: PT_UINT64) */
	unsigned long pgft_min = 0;
	extract__pgft_min(child, &pgft_min);
	auxmap__store_u64_param(auxmap, pgft_min);

	struct mm_struct *mm = NULL;
	READ_TASK_FIELD_INTO(&mm, child, mm);

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
	auxmap__store_charbuf_param(auxmap, (unsigned long)child->comm, TASK_COMM_LEN, KERNEL);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	bpf_tail_call(ctx, &extra_sched_proc_fork_calls, T1_SCHED_PROC_FORK);
	return 0;
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(t1_sched_p_fork, struct task_struct *parent, struct task_struct *child) {
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap) {
		return 0;
	}

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 15: cgroups (type: PT_CHARBUFARRAY) */
	auxmap__store_cgroups_param(auxmap, child);

	/* Parameter 16: flags (type: PT_FLAGS32) */
	uint32_t flags = 0;

	/* Since Linux 2.5.35, the flags mask must also include
	 * CLONE_SIGHAND if CLONE_THREAD is specified (and note that,
	 * since Linux 2.6.0, CLONE_SIGHAND also requires CLONE_VM to
	 * be included).
	 * Taken from https://man7.org/linux/man-pages/man2/clone.2.html
	 */
	pid_t tid = READ_TASK_FIELD(child, pid);
	pid_t tgid = READ_TASK_FIELD(child, tgid);
	if(tid != tgid) {
		flags |= PPM_CL_CLONE_THREAD | PPM_CL_CLONE_SIGHAND | PPM_CL_CLONE_VM;
	}

	/* If CLONE_FILES is set, the calling process and the child
	 * process share the same file descriptor table.
	 * Taken from https://man7.org/linux/man-pages/man2/clone.2.html
	 */
	struct files_struct *file_struct = NULL;
	struct files_struct *parent_file_struct = NULL;
	READ_TASK_FIELD_INTO(&file_struct, child, files);
	READ_TASK_FIELD_INTO(&parent_file_struct, parent, files);
	if(parent_file_struct == file_struct) {
		flags |= PPM_CL_CLONE_FILES;
	}

	/* It's possible to have a process in a PID namespace that
	 * nevertheless has tid == vtid, so we need to generate this
	 * custom flag `PPM_CL_CHILD_IN_PIDNS`.
	 */
	struct pid *pid_struct = extract__task_pid_struct(child, PIDTYPE_PID);
	struct pid_namespace *pid_namespace_struct = extract__namespace_of_pid(pid_struct);
	int pidns_level = BPF_CORE_READ(pid_namespace_struct, level);
	if(pidns_level != 0) {
		flags |= PPM_CL_CHILD_IN_PIDNS;
	}
	auxmap__store_u32_param(auxmap, flags);

	/* Parameter 17: uid (type: PT_UINT32) */
	uint32_t euid = 0;
	extract__euid(child, &euid);
	auxmap__store_u32_param(auxmap, euid);

	/* Parameter 18: gid (type: PT_UINT32) */
	uint32_t egid = 0;
	extract__egid(child, &egid);
	auxmap__store_u32_param(auxmap, egid);

	/* Parameter 19: vtid (type: PT_PID) */
	pid_t vtid = extract__task_xid_vnr(child, PIDTYPE_PID);
	auxmap__store_s64_param(auxmap, (int64_t)vtid);

	/* Parameter 20: vpid (type: PT_PID) */
	pid_t vpid = extract__task_xid_vnr(child, PIDTYPE_TGID);
	auxmap__store_s64_param(auxmap, (int64_t)vpid);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* We have to split here the bpf program, otherwise, it is too large
	 * for the verifier (limit 1000000 instructions).
	 */
	bpf_tail_call(ctx, &extra_sched_proc_fork_calls, T2_SCHED_PROC_FORK);
	return 0;
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(t2_sched_p_fork, struct task_struct *parent, struct task_struct *child) {
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap) {
		return 0;
	}

	/* Parameter 21: pid_namespace init task start_time monotonic time in ns (type: PT_UINT64) */
	auxmap__store_u64_param(auxmap, extract__task_pidns_start_time(child, PIDTYPE_TGID, 0));

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);
	return 0;
}
#endif /* CAPTURE_SCHED_PROC_EXEC */

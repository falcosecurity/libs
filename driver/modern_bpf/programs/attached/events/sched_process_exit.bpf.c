#include <helpers/interfaces/variable_size_event.h>
#include <driver/systype_compat.h>
#include <helpers/interfaces/attached_programs.h>

/* The instruction limit is 1000000, so we shouldn't have issues */
#define MAX_THREADS_GROUPS 30
#define MAX_HIERARCHY_TRAVERSE 60

/* 3 possible cases:
 * - Looping between all threads of the current thread group we don't find a valid reaper. -> return 0
 * - We cannot loop over all threads of the group due to BPF verifier limits (MAX_THREADS_GROUPS) -> return -1
 * - We find a reaper -> return its `pid`
 */
static __always_inline pid_t find_alive_thread(struct task_struct *father)
{
	struct signal_struct *signal = BPF_CORE_READ(father, signal);
	struct list_head *head = &(signal->thread_head);
	struct list_head *next_thread = BPF_CORE_READ(head, next);

	u8 cnt = 0;

	for(struct task_struct *t = container_of(next_thread, typeof(struct task_struct), thread_node);
	    next_thread != (head) && cnt < MAX_THREADS_GROUPS;
	    t = container_of(next_thread, typeof(struct task_struct), thread_node))
	{
		cnt++;
		if(!(BPF_CORE_READ(t, flags) & PF_EXITING))
		{
			return BPF_CORE_READ(t, pid);
		}
		next_thread = BPF_CORE_READ(t, thread_node.next);
	}

	/* We cannot loop over all threads, we cannot know the right reaper */
	if(cnt == MAX_THREADS_GROUPS)
	{
		return -1;
	}

	/* We didn't find it */
	return 0;
}

/* When we die, we re-parent all our children, and try to:
 * 1. give them to another thread in our thread group, if such a member exists
 * 2. give it to the first ancestor process which prctl'd itself as a
 *    child_subreaper for its children (like a service manager)
 * 3. give it to the init process (PID 1) in our pid namespace
 */
static __always_inline pid_t find_new_reaper_pid(struct task_struct *father)
{
	pid_t reaper_pid = find_alive_thread(father);

	/* - If we are not able to find the reaper due to BPF
	 * verifier limits we return `-1` immediately in this
	 * way the userspace can handle the reparenting logic
	 * without complexity limits.
	 *
	 * - If reaper_pid > 0 we find a valid reaper, we can return.
	 */
	if(reaper_pid != 0)
	{
		return reaper_pid;
	}

	struct pid *pid_struct = extract__task_pid_struct(father, PIDTYPE_PID);
	struct pid_namespace *pid_ns = extract__namespace_of_pid(pid_struct);

	/* This is the reaper of that namespace */
	struct task_struct *child_ns_reaper = BPF_CORE_READ(pid_ns, child_reaper);
	pid_t child_reaper_pid = BPF_CORE_READ(child_ns_reaper, pid);

	/* There could be a strange case in which the actual thread is the init one
	 * and we have no other threads in the same thread group, so the whole init group is dying.
	 * The kernel will destroy all the processes in that namespace. We send a reaper equal to
	 * `0` in userspace.
	 */
	if(child_ns_reaper == father)
	{
		return 0;
	}

	/* If there are no sub reapers the reaper is the init process of that namespace */
	struct signal_struct *signal = READ_TASK_FIELD(father, signal);
	if(!BPF_CORE_READ_BITFIELD_PROBED(signal, has_child_subreaper))
	{
		return child_reaper_pid;
	}

	/* This is the namespace level of the thread that is dying, we will
	 * use it to check that the reaper will be always in the same namespace.
	 */
	unsigned int father_ns_level = READ_TASK_FIELD(father, thread_pid, level);
	unsigned int current_ns_level = 0;

	/* Find the first ->is_child_subreaper ancestor in our pid_ns.
	 * We can't check with != child_reaper to ensure we do not
	 * cross the namespaces, the exiting parent could be injected
	 * by setns() + fork().
	 * We check pid->level, this is slightly more efficient than
	 * task_active_pid_ns(reaper) != task_active_pid_ns(father).
	 */
	u8 cnt = 0;

	for(struct task_struct *possible_reaper = READ_TASK_FIELD(father, real_parent); cnt < MAX_HIERARCHY_TRAVERSE;
	    possible_reaper = BPF_CORE_READ(possible_reaper, real_parent))
	{
		cnt++;
		current_ns_level = BPF_CORE_READ(possible_reaper, thread_pid, level);

		/* We are crossing the namespace or we are the child_ns_reaper */
		if(father_ns_level != current_ns_level || possible_reaper == child_ns_reaper)
		{
			return child_reaper_pid;
		}

		signal = BPF_CORE_READ(possible_reaper, signal);
		if(!BPF_CORE_READ_BITFIELD_PROBED(signal, is_child_subreaper))
		{
			continue;
		}

		/* Here again we can return -1 in case we have verifier limits issues */
		reaper_pid = find_alive_thread(possible_reaper);
		if(reaper_pid != 0)
		{
			return reaper_pid;
		}
	}

	/* We cannot traverse all the hierarchy, we cannot know the right reaper */
	if(cnt == MAX_HIERARCHY_TRAVERSE)
	{
		return -1;
	}

	return child_reaper_pid;
}

/* From linux tree: /include/trace/events/sched.h
 * TP_PROTO(struct task_struct *p)
 */
SEC("tp_btf/sched_process_exit")
int BPF_PROG(sched_proc_exit, struct task_struct *task)
{
	/* NOTE: this is a fixed-size event and so we should use the `ringbuf-approach`.
	 * Unfortunately we are hitting a sort of complexity limit in some kernel versions (<5.10)
	 * It seems like the verifier is not able to recognize the `ringbuf` pointer as a real pointer
	 * after a certain number of instructions but it considers it as an `invariant` causing a verifier error like:
	 * R1 invalid mem access 'inv'
	 * 
	 * Right now we solved it using the `auxmap-approach` but in the next future maybe we could
	 * switch again to the `ringbuf-approach`.
	 */
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_PROCEXIT_1_E);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: status (type: PT_ERRNO) */
	s32 exit_code = 0;
	READ_TASK_FIELD_INTO(&exit_code, task, exit_code);
	auxmap__store_s64_param(auxmap, (s64)exit_code);

	/* Parameter 2: ret (type: PT_ERRNO) */
	s32 ret = __WEXITSTATUS(exit_code);
	auxmap__store_s64_param(auxmap, (s64)ret);

	/* Parameter 3: sig (type: PT_SIGTYPE) */
	u8 sig = 0;
	/* If the process terminates with a signal collect it. */
	if(__WIFSIGNALED(exit_code) != 0)
	{
		sig = __WTERMSIG(exit_code);
	}
	auxmap__store_u8_param(auxmap, sig);

	/* Parameter 4: core (type: PT_UINT8) */
	u8 core = __WCOREDUMP(exit_code) != 0;
	auxmap__store_u8_param(auxmap, core);

	/* Parameter 5: reaper_tid (type: PT_PID) */
	/* This is a sort of optimization if we don't have children in the kernel
	 * we don't need a reaper and we can save some precious cycles.
	 * We send `reaper_pid==0` if the userspace still has some children
	 * it will manage them with its userspace logic.
	 */
	s32 reaper_pid = 0;
	struct list_head *head = &(task->children);
	struct list_head *next_child = BPF_CORE_READ(head, next);
	if(next_child != head)
	{
		/* We have at least one child, so we need a reaper for it */
		reaper_pid = find_new_reaper_pid(task);
	}
	/* Please note here `pid` is in kernel-lingo so it is a thread id.
	 * the thread group id is `tgid`.
	 */
	auxmap__store_s64_param(auxmap, (s64)reaper_pid);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap, ctx);

	return 0;
}

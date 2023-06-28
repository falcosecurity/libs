#include "../../event_class/event_class.h"
#include "../../helpers/proc_parsing.h"

#if defined(__NR_clone) && defined(__NR_wait4)

TEST(SyscallExit, cloneX_father)
{
	auto evt_test = get_syscall_event_test(__NR_clone, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* We scan proc before the BPF event is caught so we have
	 * to use `GREATER_EQUAL` in the assertions.
	 */
	struct proc_info info = {0};
	pid_t pid = ::getpid();
	if(!get_proc_info(pid, &info))
	{
		FAIL() << "Unable to get all the info from proc" << std::endl;
	}

	/* We need to use `SIGCHLD` otherwise the parent won't receive any signal
	 * when the child terminates. We use `CLONE_FILES` just to test the flags.
	 */
	unsigned long clone_flags = CLONE_FILES | SIGCHLD;
	unsigned long newsp = 0;
	int parent_tid = 0;
	int child_tid = 0;
	unsigned long tls = 0;
	pid_t ret_pid = 0;

	/* Please note: Some systems are compiled with kernel config like `CONFIG_CLONE_BACKWARDS2`, so the order of clone params
	 * is not the same as for all architectures. `/kernel/fork.c` from kernel source tree.
	 *
	 *  #ifdef CONFIG_CLONE_BACKWARDS
	 *	SYSCALL_DEFINE5(clone, unsigned long, clone_flags, unsigned long, newsp,  	  <-- `aarch64` and `riscv` systems use this.
	 *			int __user *, parent_tidptr,
	 *			unsigned long, tls,
	 *			int __user *, child_tidptr)
	 *	#elif defined(CONFIG_CLONE_BACKWARDS2)
	 *	SYSCALL_DEFINE5(clone, unsigned long, newsp, unsigned long, clone_flags,      <-- `s390x` systems use this.
	 *			int __user *, parent_tidptr,
	 *			int __user *, child_tidptr,
	 *			unsigned long, tls)
	 *	#elif defined(CONFIG_CLONE_BACKWARDS3)
	 *	SYSCALL_DEFINE6(clone, unsigned long, clone_flags, unsigned long, newsp,
	 *			int, stack_size,
	 *			int __user *, parent_tidptr,
	 *			int __user *, child_tidptr,
	 *			unsigned long, tls)
	 *	#else
	 *	SYSCALL_DEFINE5(clone, unsigned long, clone_flags, unsigned long, newsp,      <-- `x86_64` systems use this.
	 *			int __user *, parent_tidptr,
	 *			int __user *, child_tidptr,
	 *			unsigned long, tls)
	 *	#endif
	 *
	 */
#ifdef __s390x__
	ret_pid = syscall(__NR_clone, newsp, clone_flags, &parent_tid, &child_tid, tls);
#elif defined(__aarch64__) || defined(__riscv)
	ret_pid = syscall(__NR_clone, clone_flags, newsp, &parent_tid, tls, &child_tid);
#else
	ret_pid = syscall(__NR_clone, clone_flags, newsp, &parent_tid, &child_tid, tls);
#endif

	if(ret_pid == 0)
	{
		/* Child terminates immediately. */
		exit(EXIT_SUCCESS);
	}

	assert_syscall_state(SYSCALL_SUCCESS, "clone", ret_pid, NOT_EQUAL, -1);

	/* Catch the child before doing anything else. */
	int status = 0;
	int options = 0;
	assert_syscall_state(SYSCALL_SUCCESS, "wait4", syscall(__NR_wait4, ret_pid, &status, options, NULL), NOT_EQUAL, -1);

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure())
	{
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_PID)*/
	evt_test->assert_numeric_param(1, (int64_t)ret_pid);

	/* Parameter 2: exe (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(2, info.args[0]);

	/* Parameter 3: args (type: PT_CHARBUFARRAY) */
	/* Starting from `1` because the first is `exe`. */
	evt_test->assert_charbuf_array_param(3, &info.args[1]);

	/* Parameter 4: tid (type: PT_PID) */
	evt_test->assert_numeric_param(4, (int64_t)pid);

	/* Parameter 5: pid (type: PT_PID) */
	/* We are the main thread of the process so it's equal to `tid`. */
	evt_test->assert_numeric_param(5, (int64_t)pid);

	/* Parameter 6: ptid (type: PT_PID) */
	evt_test->assert_numeric_param(6, (int64_t)info.ppid);

	/* Parameter 7: cwd (type: PT_CHARBUF) */
	/* leave the current working directory empty like in the old probe. */
	evt_test->assert_empty_param(7);

	/* Parameter 8: fdlimit (type: PT_UINT64) */
	evt_test->assert_numeric_param(8, (uint64_t)info.file_rlimit.rlim_cur);

	/* Parameter 9: pgft_maj (type: PT_UINT64) */
	/* Right now we can't find a precise value to perform the assertion. */
	evt_test->assert_numeric_param(9, (uint64_t)0, GREATER_EQUAL);

	/* Parameter 10: pgft_min (type: PT_UINT64) */
	/* Right now we can't find a precise value to perform the assertion. */
	evt_test->assert_numeric_param(10, (uint64_t)0, GREATER_EQUAL);

	/* Parameter 11: vm_size (type: PT_UINT32) */
	evt_test->assert_numeric_param(11, (uint32_t)0, GREATER_EQUAL);

	/* Parameter 12: vm_rss (type: PT_UINT32) */
	evt_test->assert_numeric_param(12, (uint32_t)0, GREATER_EQUAL);

	/* Parameter 13: vm_swap (type: PT_UINT32) */
	evt_test->assert_numeric_param(13, (uint32_t)0, GREATER_EQUAL);

	/* Parameter 14: comm (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(14, TEST_EXECUTABLE_NAME);

	/* Parameter 15: cgroups (type: PT_CHARBUFARRAY) */
	evt_test->assert_cgroup_param(15);

	/* Parameter 16: flags (type: PT_FLAGS32) */
	evt_test->assert_numeric_param(16, (uint32_t)PPM_CL_CLONE_FILES);

	/* Parameter 17: uid (type: PT_UINT32) */
	evt_test->assert_numeric_param(17, (uint32_t)info.uid);

	/* Parameter 18: gid (type: PT_UINT32) */
	evt_test->assert_numeric_param(18, (uint32_t)info.gid);

	/* Parameter 19: vtid (type: PT_PID) */
	evt_test->assert_numeric_param(19, (int64_t)info.vtid);

	/* Parameter 20: vpid (type: PT_PID) */
	evt_test->assert_numeric_param(20, (int64_t)info.vpid);

	/* Parameter 21: pid_namespace init task start_time monotonic time in ns (type: PT_UINT64) */
	evt_test->assert_numeric_param(21, (uint64_t)0);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(21);
}

TEST(SyscallExit, cloneX_child)
{
	auto evt_test = get_syscall_event_test(__NR_clone, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Here we scan the parent just to obtain some info for the child */
	struct proc_info info = {0};
	pid_t pid = ::getpid();
	if(!get_proc_info(pid, &info))
	{
		FAIL() << "Unable to get all the info from proc" << std::endl;
	}

	/* We need to use `SIGCHLD` otherwise the parent won't receive any signal
	 * when the child terminates. We use `CLONE_FILES` just to test the flags.
	 */
	unsigned long clone_flags = CLONE_FILES | SIGCHLD;
	int parent_tid = 0;
	unsigned long newsp = 0;
	int child_tid = 0;
	unsigned long tls = 0;
	pid_t ret_pid = 0;

#ifdef __s390x__
	ret_pid = syscall(__NR_clone, newsp, clone_flags, &parent_tid, &child_tid, tls);
#elif defined(__aarch64__) || defined(__riscv)
	ret_pid = syscall(__NR_clone, clone_flags, newsp, &parent_tid, tls, &child_tid);
#else
	ret_pid = syscall(__NR_clone, clone_flags, newsp, &parent_tid, &child_tid, tls);
#endif

	if(ret_pid == 0)
	{
		/* Child terminates immediately. */
		exit(EXIT_SUCCESS);
	}

	assert_syscall_state(SYSCALL_SUCCESS, "clone", ret_pid, NOT_EQUAL, -1);

	int status = 0;
	int options = 0;
	assert_syscall_state(SYSCALL_SUCCESS, "wait4", syscall(__NR_wait4, ret_pid, &status, options, NULL), NOT_EQUAL, -1);
	if(__WEXITSTATUS(status) == EXIT_FAILURE || __WIFSIGNALED(status) != 0)
	{
		FAIL() << "Something in the child failed." << std::endl;
	}

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence(ret_pid);

	if(HasFatalFailure())
	{
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_PID)*/
	evt_test->assert_numeric_param(1, (int64_t)0);

	/* Parameter 2: exe (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(2, info.args[0]);

	/* Parameter 3: args (type: PT_CHARBUFARRAY) */
	/* Starting from `1` because the first is `exe`. */
	evt_test->assert_charbuf_array_param(3, &info.args[1]);

	/* Parameter 4: tid (type: PT_PID) */
	evt_test->assert_numeric_param(4, (int64_t)ret_pid);

	/* Parameter 5: pid (type: PT_PID) */
	/* We are the main thread of the process so it's equal to `tid`. */
	evt_test->assert_numeric_param(5, (int64_t)ret_pid);

	/* Parameter 6: ptid (type: PT_PID) */
	evt_test->assert_numeric_param(6, (int64_t)::getpid());

	/* Parameter 7: cwd (type: PT_CHARBUF) */
	/* leave the current working directory empty like in the old probe. */
	evt_test->assert_empty_param(7);

	/* Parameter 14: comm (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(14, TEST_EXECUTABLE_NAME);

	/* Parameter 15: cgroups (type: PT_CHARBUFARRAY) */
	evt_test->assert_cgroup_param(15);

	/* Parameter 16: flags (type: PT_FLAGS32) */
	evt_test->assert_numeric_param(16, (uint32_t)PPM_CL_CLONE_FILES);

	/* Parameter 21: pid_namespace init task start_time monotonic time in ns (type: PT_UINT64) */
	evt_test->assert_numeric_param(21, (uint64_t)0, GREATER_EQUAL);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(21);
}
#endif

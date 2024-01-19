#include "../../event_class/event_class.h"
#include "../../helpers/proc_parsing.h"

#if defined(__NR_clone3) && defined(__NR_wait4)

#include <linux/sched.h>

TEST(SyscallExit, clone3X_father)
{
	auto evt_test = get_syscall_event_test(__NR_clone3, EXIT_EVENT);

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
	clone_args cl_args = {0};
	cl_args.flags = CLONE_FILES;
	cl_args.exit_signal = SIGCHLD;
	pid_t ret_pid = syscall(__NR_clone3, &cl_args, sizeof(cl_args));

	if(ret_pid == 0)
	{
		/* Child terminates immediately. */
		exit(EXIT_SUCCESS);
	}

	assert_syscall_state(SYSCALL_SUCCESS, "clone3", ret_pid, NOT_EQUAL, -1);
	/* Catch the child before doing anything else. */
	int status = 0;
	int options = 0;
	assert_syscall_state(SYSCALL_SUCCESS, "wait4", syscall(__NR_wait4, ret_pid, &status, options, NULL), NOT_EQUAL,
			     -1);

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

TEST(SyscallExit, clone3X_child)
{
	auto evt_test = get_syscall_event_test(__NR_clone3, EXIT_EVENT);

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
	clone_args cl_args = {0};
	cl_args.flags = CLONE_FILES;
	cl_args.exit_signal = SIGCHLD;
	pid_t ret_pid = syscall(__NR_clone3, &cl_args, sizeof(cl_args));

	/* Child performs assertions on itself. */
	if(ret_pid == 0)
	{
		/* Child terminates immediately. */
		exit(EXIT_SUCCESS);
	}

	assert_syscall_state(SYSCALL_SUCCESS, "clone3", ret_pid, NOT_EQUAL, -1);

	int status = 0;
	int options = 0;
	assert_syscall_state(SYSCALL_SUCCESS, "wait4", syscall(__NR_wait4, ret_pid, &status, options, NULL), NOT_EQUAL,
			     -1);

	if(__WEXITSTATUS(status) == EXIT_FAILURE || __WIFSIGNALED(status) != 0)
	{
		FAIL() << "Something in the child failed." << std::endl;
	}

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->disable_capture();

	/* In some architectures we are not able to catch the `clone exit child
	 * event` from the `sys_exit` tracepoint. This is because there is no
	 * default behavior among different architectures... you can find more
	 * info in `driver/feature_gates.h`. Even if the `sched_proc_fork` tracepoint
	 * is enabled when starting the capture it will generate a `CLONE_X` event and
	 * not a `CLONE3_X` event so we need to assert the absence here.
	 */
#ifdef CAPTURE_SCHED_PROC_FORK
	evt_test->assert_event_absence(ret_pid);
#else
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
#endif
}

/* This flag was introduced together with `set_tid` field, if there is the flag
 * we should also have the `set_tid` field in struct `clone_args`
 */
#ifdef CLONE_CLEAR_SIGHAND
TEST(SyscallExit, clone3X_create_child_with_2_threads)
{
	auto evt_test = get_syscall_event_test(__NR_clone3, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Here we create a child process that will have:
	 * - a leader thread with `tid` equal to `p1_t1`
	 * - a second thread with `tid` equal to `p1_t2`.
	 */
	pid_t p1_t1 = 61001;
	pid_t p1_t2 = 61004;

	clone_args cl_args_parent = {0};
	cl_args_parent.set_tid = (uint64_t)&p1_t1;
	cl_args_parent.set_tid_size = 1;
	cl_args_parent.exit_signal = SIGCHLD;
	pid_t ret_pid = syscall(__NR_clone3, &cl_args_parent, sizeof(cl_args_parent));

	/* Create a child process that will spawn a new thread */
	if(ret_pid == 0)
	{
		/* Spawn a new thread */
		clone_args cl_args_child = {0};
		cl_args_child.set_tid = (uint64_t)&p1_t2;
		cl_args_child.set_tid_size = 1;
		/* CLONE_PARENT has no additional effects if we are spawning a thread
		 * A new thread created with CLONE_THREAD has the same parent process
		 * as the process that made the clone call (i.e., like CLONE_PARENT)
		 */
		cl_args_child.flags = CLONE_THREAD | CLONE_SIGHAND | CLONE_VM | CLONE_VFORK | CLONE_PARENT;
		pid_t child_thread = syscall(__NR_clone3, &cl_args_child, sizeof(cl_args_child));
		if(child_thread == 0)
		{
			exit(EXIT_SUCCESS);
		}
		exit(EXIT_SUCCESS);
	}

	assert_syscall_state(SYSCALL_SUCCESS, "clone3", ret_pid, NOT_EQUAL, -1);

	int status = 0;
	int options = 0;
	assert_syscall_state(SYSCALL_SUCCESS, "wait4", syscall(__NR_wait4, ret_pid, &status, options, NULL), NOT_EQUAL,
			     -1);

	if(__WEXITSTATUS(status) == EXIT_FAILURE || __WIFSIGNALED(status) != 0)
	{
		FAIL() << "Something in the child failed." << std::endl;
	}
	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->disable_capture();

#ifdef CAPTURE_SCHED_PROC_FORK
	evt_test->assert_event_absence(p1_t2);
#else
	evt_test->assert_event_presence(p1_t2);

	if(HasFatalFailure())
	{
		FAIL() << "There is a fatal failure in the child";
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_PID)*/
	evt_test->assert_numeric_param(1, (int64_t)0);

	/* Parameter 4: tid (type: PT_PID) */
	/* */
	evt_test->assert_numeric_param(4, (int64_t)p1_t2);

	/* Parameter 5: pid (type: PT_PID) */
	/* the tgid is the leader one */
	evt_test->assert_numeric_param(5, (int64_t)p1_t1);

	/* Parameter 6: ptid (type: PT_PID) */
	/* The new thread created with CLONE_THREAD has the same parent process
	 * as the process that made the clone call
	 */
	evt_test->assert_numeric_param(6, (int64_t)::gettid());

	/* Parameter 16: flags (type: PT_FLAGS32) */
	evt_test->assert_numeric_param(16, (uint32_t)PPM_CL_CLONE_THREAD | PPM_CL_CLONE_SIGHAND | PPM_CL_CLONE_VM |
						   PPM_CL_CLONE_VFORK | PPM_CL_CLONE_PARENT);

	/* Parameter 19: vtid (type: PT_PID) */
	evt_test->assert_numeric_param(19, (int64_t)p1_t2);

	/* Parameter 20: vpid (type: PT_PID) */
	evt_test->assert_numeric_param(20, (int64_t)p1_t1);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(21);
#endif
}

TEST(SyscallExit, clone3X_child_clone_parent_flag)
{
	auto evt_test = get_syscall_event_test(__NR_clone3, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Here we create a child process that will have:
	 * - a leader thread with `tid` equal to `p1_t1`
	 * - a child process with `tid` equal to `p2_t1`
	 */
	pid_t p1_t1 = 61024;
	pid_t p2_t1 = 60128;

	clone_args cl_args_parent = {0};
	cl_args_parent.set_tid = (uint64_t)&p1_t1;
	cl_args_parent.set_tid_size = 1;
	cl_args_parent.exit_signal = SIGCHLD;
	pid_t ret_pid = syscall(__NR_clone3, &cl_args_parent, sizeof(cl_args_parent));

	if(ret_pid == 0)
	{
		clone_args cl_args_child = {0};
		cl_args_child.set_tid = (uint64_t)&p2_t1;
		cl_args_child.set_tid_size = 1;
		cl_args_child.flags = CLONE_PARENT;
		cl_args_parent.exit_signal = SIGCHLD;
		pid_t second_child = syscall(__NR_clone3, &cl_args_child, sizeof(cl_args_child));
		if(second_child == 0)
		{
			exit(EXIT_SUCCESS);
		}
		if(second_child == -1)
		{
			exit(EXIT_FAILURE);
		}
		exit(EXIT_SUCCESS);
	}

	assert_syscall_state(SYSCALL_SUCCESS, "clone3", ret_pid, NOT_EQUAL, -1);

	int status = 0;
	int options = 0;

	/* Wait for the first child */
	assert_syscall_state(SYSCALL_SUCCESS, "wait4", syscall(__NR_wait4, ret_pid, &status, options, NULL), NOT_EQUAL,
			     -1);

	if(__WEXITSTATUS(status) == EXIT_FAILURE || __WIFSIGNALED(status) != 0)
	{
		FAIL() << "Something in the first child failed." << std::endl;
	}

	/* Since we are using the `CLONE_PARENT` flag the currect process is signaled also for the second child  */
	assert_syscall_state(SYSCALL_SUCCESS, "wait4", syscall(__NR_wait4, p2_t1, &status, options, NULL), NOT_EQUAL,
			     -1);

	if(__WEXITSTATUS(status) == EXIT_FAILURE || __WIFSIGNALED(status) != 0)
	{
		FAIL() << "Something in the second child failed." << std::endl;
	}

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->disable_capture();

#ifdef CAPTURE_SCHED_PROC_FORK
	evt_test->assert_event_absence(p2_t1);
#else
	evt_test->assert_event_presence(p2_t1);

	if(HasFatalFailure())
	{
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_PID)*/
	evt_test->assert_numeric_param(1, (int64_t)0);

	/* Parameter 4: tid (type: PT_PID) */
	evt_test->assert_numeric_param(4, (int64_t)p2_t1);

	/* Parameter 5: pid (type: PT_PID) */
	evt_test->assert_numeric_param(5, (int64_t)p2_t1);

	/* Parameter 6: ptid (type: PT_PID) */
	/* Thanks to the CLONE_PARENT flag the parent should be the actual process */
	evt_test->assert_numeric_param(6, (int64_t)::gettid());

	/* Parameter 16: flags (type: PT_FLAGS32) */
	evt_test->assert_numeric_param(16, (uint32_t)PPM_CL_CLONE_PARENT);

	/* Parameter 19: vtid (type: PT_PID) */
	evt_test->assert_numeric_param(19, (int64_t)p2_t1);

	/* Parameter 20: vpid (type: PT_PID) */
	evt_test->assert_numeric_param(20, (int64_t)p2_t1);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(21);
#endif
}

TEST(SyscallExit, clone3X_child_new_namespace_from_child)
{
	auto evt_test = get_syscall_event_test(__NR_clone3, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Here we create a child process in a new namespace. */
	pid_t p1_t1[2] = {1, 61032};

	clone_args cl_args = {0};
	cl_args.set_tid = (uint64_t)&p1_t1;
	cl_args.set_tid_size = 2;
	cl_args.flags = CLONE_NEWPID;
	cl_args.exit_signal = SIGCHLD;
	pid_t ret_pid = syscall(__NR_clone3, &cl_args, sizeof(cl_args));

	if(ret_pid == 0)
	{
		/* Child terminates immediately. */
		exit(EXIT_SUCCESS);
	}

	assert_syscall_state(SYSCALL_SUCCESS, "clone3", ret_pid, NOT_EQUAL, -1);

	int status = 0;
	int options = 0;
	assert_syscall_state(SYSCALL_SUCCESS, "wait4", syscall(__NR_wait4, ret_pid, &status, options, NULL), NOT_EQUAL,
			     -1);

	if(__WEXITSTATUS(status) == EXIT_FAILURE || __WIFSIGNALED(status) != 0)
	{
		FAIL() << "Something in the child failed." << std::endl;
	}

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->disable_capture();

#ifdef CAPTURE_SCHED_PROC_FORK
	evt_test->assert_event_absence(ret_pid);
#else
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

	/* Parameter 4: tid (type: PT_PID) */
	evt_test->assert_numeric_param(4, (int64_t)p1_t1[1]);

	/* Parameter 5: pid (type: PT_PID) */
	evt_test->assert_numeric_param(5, (int64_t)p1_t1[1]);

	/* Parameter 6: ptid (type: PT_PID) */
	evt_test->assert_numeric_param(6, (int64_t)::gettid());

	/* Parameter 16: flags (type: PT_FLAGS32) */
	evt_test->assert_numeric_param(16, (uint32_t)PPM_CL_CLONE_NEWPID | PPM_CL_CHILD_IN_PIDNS);

	/* Parameter 19: vtid (type: PT_PID) */
	evt_test->assert_numeric_param(19, (int64_t)p1_t1[0]);

	/* Parameter 20: vpid (type: PT_PID) */
	evt_test->assert_numeric_param(20, (int64_t)p1_t1[0]);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(21);
#endif
}

TEST(SyscallExit, clone3X_child_new_namespace_from_caller)
{
	auto evt_test = get_syscall_event_test(__NR_clone3, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Here we create a child process in a new namespace. */
	pid_t p1_t1[2] = {1, 61032};

	clone_args cl_args = {0};
	cl_args.set_tid = (uint64_t)&p1_t1;
	cl_args.set_tid_size = 2;
	cl_args.flags = CLONE_NEWPID;
	cl_args.exit_signal = SIGCHLD;
	pid_t ret_pid = syscall(__NR_clone3, &cl_args, sizeof(cl_args));

	if(ret_pid == 0)
	{
		/* Child terminates immediately. */
		exit(EXIT_SUCCESS);
	}

	assert_syscall_state(SYSCALL_SUCCESS, "clone3", ret_pid, NOT_EQUAL, -1);

	int status = 0;
	int options = 0;
	assert_syscall_state(SYSCALL_SUCCESS, "wait4", syscall(__NR_wait4, ret_pid, &status, options, NULL), NOT_EQUAL,
			     -1);

	if(__WEXITSTATUS(status) == EXIT_FAILURE || __WIFSIGNALED(status) != 0)
	{
		FAIL() << "Something in the child failed." << std::endl;
	}

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
	evt_test->assert_numeric_param(1, (int64_t)p1_t1[1]);

	/* Parameter 4: tid (type: PT_PID) */
	evt_test->assert_numeric_param(4, (int64_t)::gettid());

	/* Parameter 5: pid (type: PT_PID) */
	evt_test->assert_numeric_param(5, (int64_t)::getpid());

	/* Parameter 16: flags (type: PT_FLAGS32) */
	/* Please note that here we have `PPM_CL_CLONE_NEWPID` but not `PPM_CL_CHILD_IN_PIDNS`! */
	evt_test->assert_numeric_param(16, (uint32_t)PPM_CL_CLONE_NEWPID);

	/* Parameter 19: vtid (type: PT_PID) */
	evt_test->assert_numeric_param(19, (int64_t)::gettid());

	/* Parameter 20: vpid (type: PT_PID) */
	evt_test->assert_numeric_param(20, (int64_t)::getpid());

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(21);
}

TEST(SyscallExit, clone3X_child_new_namespace_create_thread)
{
	auto evt_test = get_syscall_event_test(__NR_clone3, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Here we create a child process in a new namespace.
	 * The child process will have `tid` equal to `p1_t1`.
	 * The child process will create a new thread with `tid` equal to `p1_t2`
	 */
	pid_t p1_t1[2] = {1, 61032};
	/* Please note that a process can have the same pid number in different namespaces */
	pid_t p1_t2[2] = {61036, 61036};

	clone_args cl_args = {0};
	cl_args.set_tid = (uint64_t)&p1_t1;
	cl_args.set_tid_size = 2;
	cl_args.flags = CLONE_NEWPID;
	cl_args.exit_signal = SIGCHLD;
	pid_t ret_pid = syscall(__NR_clone3, &cl_args, sizeof(cl_args));

	if(ret_pid == 0)
	{
		/* Spawn a new thread */
		clone_args cl_args_child = {0};
		cl_args_child.set_tid = (uint64_t)&p1_t2;
		cl_args_child.set_tid_size = 2;
		cl_args_child.flags = CLONE_THREAD | CLONE_SIGHAND | CLONE_VM | CLONE_VFORK;
		pid_t child_thread = syscall(__NR_clone3, &cl_args_child, sizeof(cl_args_child));
		if(child_thread == 0)
		{
			exit(EXIT_SUCCESS);
		}
		exit(EXIT_SUCCESS);
	}

	assert_syscall_state(SYSCALL_SUCCESS, "clone3", ret_pid, NOT_EQUAL, -1);

	int status = 0;
	int options = 0;
	assert_syscall_state(SYSCALL_SUCCESS, "wait4", syscall(__NR_wait4, ret_pid, &status, options, NULL), NOT_EQUAL,
			     -1);

	if(__WEXITSTATUS(status) == EXIT_FAILURE || __WIFSIGNALED(status) != 0)
	{
		FAIL() << "Something in the child failed." << std::endl;
	}

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->disable_capture();

#ifdef CAPTURE_SCHED_PROC_FORK
	evt_test->assert_event_absence(p1_t2[1]);
#else
	evt_test->assert_event_presence(p1_t2[1]);

	if(HasFatalFailure())
	{
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_PID)*/
	evt_test->assert_numeric_param(1, (int64_t)0);

	/* Parameter 4: tid (type: PT_PID) */
	evt_test->assert_numeric_param(4, (int64_t)p1_t2[1]);

	/* Parameter 5: pid (type: PT_PID) */
	evt_test->assert_numeric_param(5, (int64_t)p1_t1[1]);

	/* Parameter 6: ptid (type: PT_PID) */
	evt_test->assert_numeric_param(6, (int64_t)::gettid());

	/* Parameter 16: flags (type: PT_FLAGS32) */
	evt_test->assert_numeric_param(16, (uint32_t)PPM_CL_CLONE_THREAD | PPM_CL_CLONE_SIGHAND | PPM_CL_CLONE_VM |
						   PPM_CL_CLONE_VFORK | PPM_CL_CHILD_IN_PIDNS);

	/* Parameter 19: vtid (type: PT_PID) */
	evt_test->assert_numeric_param(19, (int64_t)p1_t2[0]);

	/* Parameter 20: vpid (type: PT_PID) */
	evt_test->assert_numeric_param(20, (int64_t)p1_t1[0]);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(21);
#endif
}

#endif /* CLONE_CLEAR_SIGHAND */

#endif

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
	struct clone_args cl_args = {0};
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
	struct clone_args cl_args = {0};
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
	assert_syscall_state(SYSCALL_SUCCESS, "wait4", syscall(__NR_wait4, ret_pid, &status, options, NULL), NOT_EQUAL, -1);

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
	 * - a leader thread with `tid` equal to `leader_tid`
	 * - a second thread with `tid` equal to `second_tid`.
	 */
	pid_t leader_tid = 61001;
	pid_t second_tid = 61004;

	struct clone_args cl_args_parent = {0};
	cl_args_parent.set_tid = (uint64_t)&leader_tid;
	cl_args_parent.set_tid_size = 1;
	cl_args_parent.exit_signal = SIGCHLD;
	pid_t ret_pid = syscall(__NR_clone3, &cl_args_parent, sizeof(cl_args_parent));

	/* Create a child process that will spawn a new thread */
	if(ret_pid == 0)
	{
		/* Spawn a new thread */
		struct clone_args cl_args_child = {0};
		cl_args_child.set_tid = (uint64_t)&second_tid;
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
	assert_syscall_state(SYSCALL_SUCCESS, "wait4", syscall(__NR_wait4, ret_pid, &status, options, NULL), NOT_EQUAL, -1);

	if(__WEXITSTATUS(status) == EXIT_FAILURE || __WIFSIGNALED(status) != 0)
	{
		FAIL() << "Something in the child failed." << std::endl;
	}
	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->disable_capture();

#ifdef CAPTURE_SCHED_PROC_FORK
	evt_test->assert_event_absence(second_tid);
#else
	evt_test->assert_event_presence(second_tid);

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
	evt_test->assert_numeric_param(4, (int64_t)second_tid);

	/* Parameter 5: pid (type: PT_PID) */
	/* the tgid is the leader one */
	evt_test->assert_numeric_param(5, (int64_t)leader_tid);

	/* Parameter 6: ptid (type: PT_PID) */
	/* The new thread created with CLONE_THREAD has the same parent process
	 * as the process that made the clone call
	 */
	evt_test->assert_numeric_param(6, (int64_t)::getpid());

	/* Parameter 14: comm (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(14, TEST_EXECUTABLE_NAME);

	/* Parameter 16: flags (type: PT_FLAGS32) */
	evt_test->assert_numeric_param(16, (uint32_t)PPM_CL_CLONE_THREAD | PPM_CL_CLONE_SIGHAND | PPM_CL_CLONE_VM | PPM_CL_CLONE_VFORK | PPM_CL_CLONE_PARENT);

	/* Parameter 19: vtid (type: PT_PID) */
	evt_test->assert_numeric_param(19, (int64_t)second_tid);

	/* Parameter 20: vpid (type: PT_PID) */
	evt_test->assert_numeric_param(20, (int64_t)leader_tid);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(21);
#endif
}

TEST(SyscallExit, clone3X_create_child_with_3_threads)
{
	auto evt_test = get_syscall_event_test(__NR_clone3, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Here we create a child process that will have:
	 * - a leader thread with `tid` equal to `leader_tid`
	 * - a second thread with `tid` equal to `second_tid`.
	 * - a third thread with `tid` equal to `third_tid`.
	 */
	pid_t leader_tid = 61001;
	pid_t second_tid = 61004;
	pid_t third_tid = 61008;

	struct clone_args cl_args_parent = {0};
	cl_args_parent.set_tid = (uint64_t)&leader_tid;
	cl_args_parent.set_tid_size = 1;
	cl_args_parent.exit_signal = SIGCHLD;
	pid_t ret_pid = syscall(__NR_clone3, &cl_args_parent, sizeof(cl_args_parent));

	/* Create a child process that will spawn a new thread */
	if(ret_pid == 0)
	{
		/* Spawn a new thread */
		struct clone_args cl_args_child = {0};
		cl_args_child.set_tid = (uint64_t)&second_tid;
		cl_args_child.set_tid_size = 1;
		cl_args_child.flags = CLONE_THREAD | CLONE_SIGHAND | CLONE_VM | CLONE_VFORK;
		pid_t child_thread = syscall(__NR_clone3, &cl_args_child, sizeof(cl_args_child));
		if(child_thread == 0)
		{
			struct clone_args cl_args_child2 = {0};
			cl_args_child2.set_tid = (uint64_t)&third_tid;
			cl_args_child2.set_tid_size = 1;
			cl_args_child2.flags = CLONE_THREAD | CLONE_SIGHAND | CLONE_VM | CLONE_VFORK;
			pid_t child_thread2 = syscall(__NR_clone3, &cl_args_child2, sizeof(cl_args_child2));
			if(child_thread2 == 0)
			{
				exit(EXIT_SUCCESS);
			}
			exit(EXIT_SUCCESS);
		}
		exit(EXIT_SUCCESS);
	}

	assert_syscall_state(SYSCALL_SUCCESS, "clone3", ret_pid, NOT_EQUAL, -1);

	int status = 0;
	int options = 0;
	assert_syscall_state(SYSCALL_SUCCESS, "wait4", syscall(__NR_wait4, ret_pid, &status, options, NULL), NOT_EQUAL, -1);

	if(__WEXITSTATUS(status) == EXIT_FAILURE || __WIFSIGNALED(status) != 0)
	{
		FAIL() << "Something in the child failed." << std::endl;
	}
	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->disable_capture();

#ifdef CAPTURE_SCHED_PROC_FORK
	evt_test->assert_event_absence(third_tid);
#else
	evt_test->assert_event_presence(third_tid);

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
	evt_test->assert_numeric_param(4, (int64_t)third_tid);

	/* Parameter 5: pid (type: PT_PID) */
	evt_test->assert_numeric_param(5, (int64_t)leader_tid);

	/* Parameter 6: ptid (type: PT_PID) */
	/* The new thread created with CLONE_THREAD has the same parent process
	 * as the process that made the clone call
	 */
	evt_test->assert_numeric_param(6, (int64_t)::getpid());

	/* Parameter 14: comm (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(14, TEST_EXECUTABLE_NAME);

	/* Parameter 16: flags (type: PT_FLAGS32) */
	evt_test->assert_numeric_param(16, (uint32_t)PPM_CL_CLONE_THREAD | PPM_CL_CLONE_SIGHAND | PPM_CL_CLONE_VM | PPM_CL_CLONE_VFORK);

	/* Parameter 19: vtid (type: PT_PID) */
	evt_test->assert_numeric_param(19, (int64_t)third_tid);

	/* Parameter 20: vpid (type: PT_PID) */
	evt_test->assert_numeric_param(20, (int64_t)leader_tid);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(21);
#endif
}

TEST(SyscallExit, clone3X_create_child_process_from_a_child_thread)
{
	auto evt_test = get_syscall_event_test(__NR_clone3, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Here we create a child process that will have:
	 * - a leader thread with `tid` equal to `leader_tid`
	 * - a second thread with `tid` equal to `second_tid`.
	 * - and a second child process with `tid` equal to `second_tid` created by the second thread
	 */
	pid_t leader_tid = 61001;
	pid_t second_tid = 61004;
	pid_t child_process_tid = 61008;

	struct clone_args cl_args_parent = {0};
	cl_args_parent.set_tid = (uint64_t)&leader_tid;
	cl_args_parent.set_tid_size = 1;
	cl_args_parent.exit_signal = SIGCHLD;
	pid_t ret_pid = syscall(__NR_clone3, &cl_args_parent, sizeof(cl_args_parent));

	/* Create a child process that will spawn a new thread */
	if(ret_pid == 0)
	{
		/* Spawn a new thread */
		struct clone_args cl_args_child = {0};
		cl_args_child.set_tid = (uint64_t)&second_tid;
		cl_args_child.set_tid_size = 1;
		cl_args_child.flags = CLONE_THREAD | CLONE_SIGHAND | CLONE_VM | CLONE_VFORK;
		pid_t child_thread = syscall(__NR_clone3, &cl_args_child, sizeof(cl_args_child));
		if(child_thread == 0)
		{
			struct clone_args cl_args_child2 = {0};
			cl_args_child2.set_tid = (uint64_t)&child_process_tid;
			cl_args_child2.set_tid_size = 1;
			cl_args_child2.exit_signal = SIGCHLD;
			pid_t child_thread2 = syscall(__NR_clone3, &cl_args_child2, sizeof(cl_args_child2));
			if(child_thread2 == 0)
			{
				exit(EXIT_SUCCESS);
			}

			int status = 0;
			int options = 0;
			syscall(__NR_wait4, child_thread2, &status, options, NULL);
			exit(EXIT_SUCCESS);
		}
		exit(EXIT_SUCCESS);
	}

	assert_syscall_state(SYSCALL_SUCCESS, "clone3", ret_pid, NOT_EQUAL, -1);

	int status = 0;
	int options = 0;
	assert_syscall_state(SYSCALL_SUCCESS, "wait4", syscall(__NR_wait4, ret_pid, &status, options, NULL), NOT_EQUAL, -1);

	if(__WEXITSTATUS(status) == EXIT_FAILURE || __WIFSIGNALED(status) != 0)
	{
		FAIL() << "Something in the child failed." << std::endl;
	}
	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->disable_capture();

#ifdef CAPTURE_SCHED_PROC_FORK
	evt_test->assert_event_absence(child_process_tid);
#else
	evt_test->assert_event_presence(child_process_tid);

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
	evt_test->assert_numeric_param(4, (int64_t)child_process_tid);

	/* Parameter 5: pid (type: PT_PID) */
	/* this is a new process with just one leader thread so `pid == tid` */
	evt_test->assert_numeric_param(5, (int64_t)child_process_tid);

	/* Parameter 6: ptid (type: PT_PID) */
	/* As a `ptid` we return the tgid of the parent, so in this case the leader
	 * of the first child.
	 */
	evt_test->assert_numeric_param(6, (int64_t)leader_tid);

	/* Parameter 14: comm (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(14, TEST_EXECUTABLE_NAME);

	/* Parameter 16: flags (type: PT_FLAGS32) */
	evt_test->assert_numeric_param(16, (uint32_t)0);

	/* Parameter 19: vtid (type: PT_PID) */
	evt_test->assert_numeric_param(19, (int64_t)child_process_tid);

	/* Parameter 20: vpid (type: PT_PID) */
	evt_test->assert_numeric_param(20, (int64_t)child_process_tid);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(21);
#endif
}

TEST(SyscallExit, clone3X_child_new_namespace)
{
	auto evt_test = get_syscall_event_test(__NR_clone3, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Here we create a child process in a new namespace.
	 * The child process will have `tid` equal to `child_tid`
	 */
	pid_t child_tid[2] = {};
	/* pid in the innermost namespace. We should have the init process for the new namespace */
	child_tid[0] = 1;
	/* pid in the outermost namespace. */
	child_tid[1] = 61032;

	struct clone_args cl_args = {0};
	cl_args.set_tid = (uint64_t)&child_tid;
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
	assert_syscall_state(SYSCALL_SUCCESS, "wait4", syscall(__NR_wait4, ret_pid, &status, options, NULL), NOT_EQUAL, -1);

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
	evt_test->assert_numeric_param(4, (int64_t)child_tid[1]);

	/* Parameter 5: pid (type: PT_PID) */
	evt_test->assert_numeric_param(5, (int64_t)child_tid[1]);

	/* Parameter 6: ptid (type: PT_PID) */
	evt_test->assert_numeric_param(6, (int64_t)::getpid());

	/* Parameter 14: comm (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(14, TEST_EXECUTABLE_NAME);

	/* Parameter 16: flags (type: PT_FLAGS32) */
	evt_test->assert_numeric_param(16, (uint32_t)PPM_CL_CLONE_NEWPID | PPM_CL_CHILD_IN_PIDNS);

	/* Parameter 19: vtid (type: PT_PID) */
	evt_test->assert_numeric_param(19, (int64_t)child_tid[0]);

	/* Parameter 20: vpid (type: PT_PID) */
	evt_test->assert_numeric_param(20, (int64_t)child_tid[0]);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(21);
#endif
}

TEST(SyscallExit, clone3X_child_new_namespace_create_thread)
{
	auto evt_test = get_syscall_event_test(__NR_clone3, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Here we create a child process in a new namespace.
	 * The child process will have `tid` equal to `child_tid`.
	 * The child process will create a new thread with `tid` equal to `thread_child_tid`
	 */
	pid_t child_tid[2] = {};
	/* pid in the innermost namespace. We should have the init process for the new namespace */
	child_tid[0] = 1;
	/* pid in the outermost namespace. */
	child_tid[1] = 61032;

	pid_t thread_child_tid[2] = {};
	/* Please note that a process can have the same pid number in different namespaces */
	/* pid in the innermost namespace. */
	thread_child_tid[0] = 61036;
	/* pid in the outermost namespace. */
	thread_child_tid[1] = 61036;

	struct clone_args cl_args = {0};
	cl_args.set_tid = (uint64_t)&child_tid;
	cl_args.set_tid_size = 2;
	cl_args.flags = CLONE_NEWPID;
	cl_args.exit_signal = SIGCHLD;
	pid_t ret_pid = syscall(__NR_clone3, &cl_args, sizeof(cl_args));

	if(ret_pid == 0)
	{
		/* Spawn a new thread */
		struct clone_args cl_args_child = {0};
		cl_args_child.set_tid = (uint64_t)&thread_child_tid;
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
	assert_syscall_state(SYSCALL_SUCCESS, "wait4", syscall(__NR_wait4, ret_pid, &status, options, NULL), NOT_EQUAL, -1);

	if(__WEXITSTATUS(status) == EXIT_FAILURE || __WIFSIGNALED(status) != 0)
	{
		FAIL() << "Something in the child failed." << std::endl;
	}

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->disable_capture();

	/* `thread_child_tid[1]` is the pid in the outermost namespace. */

#ifdef CAPTURE_SCHED_PROC_FORK
	evt_test->assert_event_absence(thread_child_tid[1]);
#else
	evt_test->assert_event_presence(thread_child_tid[1]);

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
	evt_test->assert_numeric_param(4, (int64_t)thread_child_tid[1]);

	/* Parameter 5: pid (type: PT_PID) */
	/* the tgid is the leader one */
	evt_test->assert_numeric_param(5, (int64_t)child_tid[1]);

	/* Parameter 6: ptid (type: PT_PID) */
	evt_test->assert_numeric_param(6, (int64_t)::getpid());

	/* Parameter 14: comm (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(14, TEST_EXECUTABLE_NAME);

	/* Parameter 16: flags (type: PT_FLAGS32) */
	evt_test->assert_numeric_param(16, (uint32_t)PPM_CL_CLONE_THREAD | PPM_CL_CLONE_SIGHAND | PPM_CL_CLONE_VM | PPM_CL_CLONE_VFORK | PPM_CL_CHILD_IN_PIDNS);

	/* Parameter 19: vtid (type: PT_PID) */
	evt_test->assert_numeric_param(19, (int64_t)thread_child_tid[0]);

	/* Parameter 20: vpid (type: PT_PID) */
	evt_test->assert_numeric_param(20, (int64_t)child_tid[0]);

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
	 * - a leader thread with `tid` equal to `leader_tid`
	 * - a child process with `tid` equal to `second_child_tid`
	 */
	pid_t leader_tid = 61024;
	pid_t second_child_tid = 60128;

	struct clone_args cl_args_parent = {0};
	cl_args_parent.set_tid = (uint64_t)&leader_tid;
	cl_args_parent.set_tid_size = 1;
	cl_args_parent.exit_signal = SIGCHLD;
	pid_t ret_pid = syscall(__NR_clone3, &cl_args_parent, sizeof(cl_args_parent));

	if(ret_pid == 0)
	{
		struct clone_args cl_args_child = {0};
		cl_args_child.set_tid = (uint64_t)&second_child_tid;
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
	assert_syscall_state(SYSCALL_SUCCESS, "wait4", syscall(__NR_wait4, ret_pid, &status, options, NULL), NOT_EQUAL, -1);

	if(__WEXITSTATUS(status) == EXIT_FAILURE || __WIFSIGNALED(status) != 0)
	{
		FAIL() << "Something in the first child failed." << std::endl;
	}

	/* Since we are using the `CLONE_PARENT` flag the currect process is signaled also for the second child  */
	assert_syscall_state(SYSCALL_SUCCESS, "wait4", syscall(__NR_wait4, second_child_tid, &status, options, NULL), NOT_EQUAL, -1);

	if(__WEXITSTATUS(status) == EXIT_FAILURE || __WIFSIGNALED(status) != 0)
	{
		FAIL() << "Something in the second child failed." << std::endl;
	}

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->disable_capture();

#ifdef CAPTURE_SCHED_PROC_FORK
	evt_test->assert_event_absence(second_child_tid);
#else
	evt_test->assert_event_presence(second_child_tid);

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
	evt_test->assert_numeric_param(4, (int64_t)second_child_tid);

	/* Parameter 5: pid (type: PT_PID) */
	evt_test->assert_numeric_param(5, (int64_t)second_child_tid);

	/* Parameter 6: ptid (type: PT_PID) */
	/* Thanks to the CLONE_PARENT flag the parent should be the actual process */
	evt_test->assert_numeric_param(6, (int64_t)::getpid());

	/* Parameter 14: comm (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(14, TEST_EXECUTABLE_NAME);

	/* Parameter 16: flags (type: PT_FLAGS32) */
	evt_test->assert_numeric_param(16, (uint32_t)PPM_CL_CLONE_PARENT);

	/* Parameter 19: vtid (type: PT_PID) */
	evt_test->assert_numeric_param(19, (int64_t)second_child_tid);

	/* Parameter 20: vpid (type: PT_PID) */
	evt_test->assert_numeric_param(20, (int64_t)second_child_tid);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(21);
#endif
}
#endif /* CLONE_CLEAR_SIGHAND */

#endif

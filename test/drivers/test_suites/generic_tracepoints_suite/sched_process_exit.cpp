#include "../../event_class/event_class.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>

#if defined(__NR_clone3) && defined(__NR_wait4)

#include <linux/sched.h>

TEST(GenericTracepoints, sched_proc_exit_no_children)
{
	auto evt_test = get_generic_event_test(PPM_SC_SCHED_PROCESS_EXIT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* We need to use `SIGCHLD` otherwise the parent won't receive any signal
	 * when the child terminates.
	 */
	clone_args cl_args = {};
	cl_args.exit_signal = SIGCHLD;
	pid_t ret_pid = syscall(__NR_clone3, &cl_args, sizeof(cl_args));

	if(ret_pid == 0)
	{
		/* Child terminates immediately. */
		exit(5);
	}

	assert_syscall_state(SYSCALL_SUCCESS, "clone3", ret_pid, NOT_EQUAL, -1);

	/* Catch the child before doing anything else. */
	int status = 0;
	int options = 0;
	assert_syscall_state(SYSCALL_SUCCESS, "wait4", syscall(__NR_wait4, ret_pid, &status, options, NULL), NOT_EQUAL,
			     -1);

	uint8_t sig = 0;
	if(__WIFSIGNALED(status) != 0)
	{
		sig = __WTERMSIG(status);
	}

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	/* The sched_process_exit hook is called by the thread
	 * that is going to die and it doesn't have children
	 */
	evt_test->assert_event_presence(ret_pid);

	if(HasFatalFailure())
	{
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: status (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)status);

	/* Parameter 2: ret (type: PT_ERRNO) */
	evt_test->assert_numeric_param(2, (int64_t)__WEXITSTATUS(status));

	/* Parameter 3: sig (type: PT_SIGTYPE) */
	evt_test->assert_numeric_param(3, (uint8_t)sig);

	/* Parameter 4: core (type: PT_UINT8) */
	evt_test->assert_numeric_param(4, (uint8_t)(__WCOREDUMP(status) != 0));

	/* Parameter 5: reaper_tid (type: PT_PID) */
	/* The dead thread has no children so the reaper is 0 */
	evt_test->assert_numeric_param(5, (int64_t)0);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

/* This flag was introduced together with `set_tid` field, if there is the flag
 * we should also have the `set_tid` field in struct `clone_args`
 */
#if defined(__NR_prctl) && defined(CLONE_CLEAR_SIGHAND)
#include <sys/prctl.h>

TEST(GenericTracepoints, sched_proc_exit_prctl_subreaper)
{
	auto evt_test = get_generic_event_test(PPM_SC_SCHED_PROCESS_EXIT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* - p1_t1 (we set it as a sub_reaper through `prctl`)
	 *  - p2_t1
	 *   - p3_t1
	 *
	 * when `p2_t1` dies we should see p1_t1 has a new reaper
	 */
	pid_t p1_t1 = 61024;
	pid_t p2_t1 = 61030;
	pid_t p3_t1 = 61050;

	clone_args cl_args_parent = {};
	cl_args_parent.set_tid = (uint64_t)&p1_t1;
	cl_args_parent.set_tid_size = 1;
	cl_args_parent.exit_signal = SIGCHLD;
	pid_t p1_t1_pid = syscall(__NR_clone3, &cl_args_parent, sizeof(cl_args_parent));

	if(p1_t1_pid == 0)
	{
		/* p1_t1 calls prctl */
		if(syscall(__NR_prctl, PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) == -1)
		{
			exit(EXIT_FAILURE);
		}

		clone_args cl_args_child = {};
		cl_args_child.set_tid = (uint64_t)&p2_t1;
		cl_args_child.set_tid_size = 1;
		cl_args_child.exit_signal = SIGCHLD;
		pid_t p2_t1_pid = syscall(__NR_clone3, &cl_args_child, sizeof(cl_args_child));
		if(p2_t1_pid == 0)
		{
			cl_args_child.set_tid = (uint64_t)&p3_t1;
			cl_args_child.set_tid_size = 1;
			cl_args_child.exit_signal = SIGCHLD;
			pid_t p3_t1_pid = syscall(__NR_clone3, &cl_args_child, sizeof(cl_args_child));
			if(p3_t1_pid == 0)
			{
				sleep(1);
				exit(EXIT_SUCCESS);
			}
			if(p3_t1_pid == -1)
			{
				exit(EXIT_FAILURE);
			}
			/* p2_t1 dies we should reparent p3_t1 to p1_t1 since it is a reaper */
			exit(EXIT_SUCCESS);
		}
		if(p2_t1_pid == -1)
		{
			exit(EXIT_FAILURE);
		}
		int status = 0;
		int options = 0;

		if(syscall(__NR_wait4, p2_t1, &status, options, NULL) == -1)
		{
			exit(EXIT_FAILURE);
		}
		if(syscall(__NR_wait4, p3_t1, &status, options, NULL) == -1)
		{
			exit(EXIT_FAILURE);
		}

		exit(EXIT_SUCCESS);
	}

	assert_syscall_state(SYSCALL_SUCCESS, "clone3", p1_t1_pid, NOT_EQUAL, -1);

	int status = 0;
	int options = 0;

	/* Wait for the first child */
	assert_syscall_state(SYSCALL_SUCCESS, "wait4", syscall(__NR_wait4, p1_t1_pid, &status, options, NULL),
			     NOT_EQUAL, -1);

	if(__WEXITSTATUS(status) == EXIT_FAILURE || __WIFSIGNALED(status) != 0)
	{
		FAIL() << "Something in the first child failed." << std::endl;
	}

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence(p2_t1);

	if(HasFatalFailure())
	{
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 5: reaper_tid (type: PT_PID) */
	evt_test->assert_numeric_param(5, (int64_t)p1_t1);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

TEST(GenericTracepoints, sched_proc_exit_child_namespace_reaper)
{
	auto evt_test = get_generic_event_test(PPM_SC_SCHED_PROCESS_EXIT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* - p1_t1 (this is the reaper of the namespace, init)
	 *  - p2_t1
	 *   - p3_t1
	 *
	 * when `p2_t1` dies we should see p1_t1 has a new reaper
	 */

	/* The first pid is the one in the innermost namespace */
	pid_t p1_t1[2] = {1, 59024};
	pid_t p2_t1[2] = {2, 59025};
	pid_t p3_t1[2] = {3, 59026};

	/* p1_t1 is in the new namespace */
	clone_args cl_args_parent = {};
	cl_args_parent.set_tid = (uint64_t)&p1_t1;
	cl_args_parent.set_tid_size = 2;
	cl_args_parent.flags = CLONE_NEWPID;
	cl_args_parent.exit_signal = SIGCHLD;
	pid_t p1_t1_pid = syscall(__NR_clone3, &cl_args_parent, sizeof(cl_args_parent));

	if(p1_t1_pid == 0)
	{
		clone_args cl_args_child = {};
		cl_args_child.set_tid = (uint64_t)&p2_t1;
		cl_args_child.set_tid_size = 2;
		cl_args_child.exit_signal = SIGCHLD;
		pid_t p2_t1_pid = syscall(__NR_clone3, &cl_args_child, sizeof(cl_args_child));
		if(p2_t1_pid == 0)
		{
			cl_args_child.set_tid = (uint64_t)&p3_t1;
			cl_args_child.set_tid_size = 2;
			cl_args_child.exit_signal = SIGCHLD;
			pid_t p3_t1_pid = syscall(__NR_clone3, &cl_args_child, sizeof(cl_args_child));
			if(p3_t1_pid == 0)
			{
				sleep(1);
				exit(EXIT_SUCCESS);
			}
			if(p3_t1_pid == -1)
			{
				exit(EXIT_FAILURE);
			}
			/* p2_t1 dies we should reparent p3_t1 to p1_t1 since it is a reaper */
			exit(EXIT_SUCCESS);
		}
		if(p2_t1_pid == -1)
		{
			exit(EXIT_FAILURE);
		}
		int status = 0;
		int options = 0;

		/* we are inside the namespace we need to use the right pids */
		if(syscall(__NR_wait4, p2_t1[0], &status, options, NULL) == -1)
		{
			exit(EXIT_FAILURE);
		}
		if(syscall(__NR_wait4, p3_t1[0], &status, options, NULL) == -1)
		{
			exit(EXIT_FAILURE);
		}

		exit(EXIT_SUCCESS);
	}

	assert_syscall_state(SYSCALL_SUCCESS, "clone3", p1_t1_pid, NOT_EQUAL, -1);

	int status = 0;
	int options = 0;

	/* Wait for the first child */
	assert_syscall_state(SYSCALL_SUCCESS, "wait4", syscall(__NR_wait4, p1_t1_pid, &status, options, NULL),
			     NOT_EQUAL, -1);

	if(__WEXITSTATUS(status) == EXIT_FAILURE || __WIFSIGNALED(status) != 0)
	{
		FAIL() << "Something in the first child failed." << std::endl;
	}

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence(p2_t1[1]);

	if(HasFatalFailure())
	{
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 5: reaper_tid (type: PT_PID) */
	evt_test->assert_numeric_param(5, (int64_t)p1_t1[1]);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

TEST(GenericTracepoints, sched_proc_exit_child_namespace_reaper_die)
{
	auto evt_test = get_generic_event_test(PPM_SC_SCHED_PROCESS_EXIT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* - p1_t1 (init process)
	 *  - p2_t1
	 *
	 * when `p1_t1` dies we should see `0` has a new reaper because
	 * it was the last init process in the thread group
	 */

	/* The first pid is the one in the innermost namespace */
	pid_t p1_t1[2] = {1, 59024};
	pid_t p2_t1[2] = {2, 59025};

	/* p1_t1 is in the new namespace */
	clone_args cl_args_parent = {};
	cl_args_parent.set_tid = (uint64_t)&p1_t1;
	cl_args_parent.set_tid_size = 2;
	cl_args_parent.flags = CLONE_NEWPID;
	cl_args_parent.exit_signal = SIGCHLD;
	pid_t p1_t1_pid = syscall(__NR_clone3, &cl_args_parent, sizeof(cl_args_parent));

	if(p1_t1_pid == 0)
	{
		clone_args cl_args_child = {};
		cl_args_child.set_tid = (uint64_t)&p2_t1;
		cl_args_child.set_tid_size = 2;
		cl_args_parent.exit_signal = SIGCHLD;
		pid_t p2_t1_pid = syscall(__NR_clone3, &cl_args_child, sizeof(cl_args_child));
		if(p2_t1_pid == 0)
		{
			sleep(20);
			exit(EXIT_SUCCESS);
		}
		if(p2_t1_pid == -1)
		{
			exit(EXIT_FAILURE);
		}
		exit(EXIT_SUCCESS);
	}

	assert_syscall_state(SYSCALL_SUCCESS, "clone3", p1_t1_pid, NOT_EQUAL, -1);

	int status = 0;
	int options = 0;

	/* Wait for the first child */
	assert_syscall_state(SYSCALL_SUCCESS, "wait4", syscall(__NR_wait4, p1_t1_pid, &status, options, NULL),
			     NOT_EQUAL, -1);

	if(__WEXITSTATUS(status) == EXIT_FAILURE || __WIFSIGNALED(status) != 0)
	{
		FAIL() << "Something in the first child failed." << std::endl;
	}

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence(p1_t1[1]);

	if(HasFatalFailure())
	{
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 5: reaper_tid (type: PT_PID) */
	/*dies we should see `0` has a new reaper because it was the last init process */
	evt_test->assert_numeric_param(5, (int64_t)0);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

#ifdef __NR_kill
static int child_func(void* arg)
{
	pid_t p2_t1 = 57006;
	clone_args cl_args_child = {};
	cl_args_child.set_tid = (uint64_t)&p2_t1;
	cl_args_child.set_tid_size = 1;
	pid_t p2_t1_pid = syscall(__NR_clone3, &cl_args_child, sizeof(cl_args_child));
	if(p2_t1_pid == 0)
	{
		sleep(1);
		return 0;
	}
	if(p2_t1_pid == -1)
	{
		exit(EXIT_FAILURE);
	}
	return 0;
}

TEST(GenericTracepoints, sched_proc_exit_reaper_in_the_same_group)
{
	auto evt_test = get_generic_event_test(PPM_SC_SCHED_PROCESS_EXIT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* - current thread
	 * - p1_t2
	 *  - p2_t1
	 *
	 * when `p1_t2` dies we should see the current thread as a repaer
	 */

	const int STACK_SIZE = 65536;
	char* stack = (char*)malloc(STACK_SIZE);
	if(!stack)
	{
		exit(EXIT_FAILURE);
	}

	/* Create a new thread */
	unsigned long flags =
		CLONE_THREAD | CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SYSVSEM | CLONE_SIGHAND | SIGCHLD;
	pid_t p1_t2_tid = clone(child_func, stack + STACK_SIZE, flags, NULL);

	assert_syscall_state(SYSCALL_SUCCESS, "clone", p1_t2_tid, NOT_EQUAL, -1);

	/* we try to sleep for 2 sec and then we kill the thread if present */
	sleep(2);
	syscall(__NR_kill, p1_t2_tid, SIGTERM);

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence(p1_t2_tid);

	if(HasFatalFailure())
	{
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 5: reaper_tid (type: PT_PID) */
	evt_test->assert_numeric_param(5, (int64_t)getpid());

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}
#endif
#endif
#endif

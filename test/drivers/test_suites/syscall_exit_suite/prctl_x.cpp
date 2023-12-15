#include "../../event_class/event_class.h"

#if defined(__NR_prctl) && defined(__NR_clone3) && defined(__NR_wait4)

#include <linux/sched.h>
#include <sys/prctl.h>

TEST(SyscallExit, prctlX_failure)
{
	auto evt_test = get_syscall_event_test(__NR_prctl, EXIT_EVENT);
	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int option = -3;
	unsigned long arg2 = -3;
	unsigned long arg3 = 0;
	unsigned long arg4 = 0;
	unsigned long arg5 = 0;

	/*
	 * Call the `prctl`
	 */

	assert_syscall_state(SYSCALL_FAILURE, "prctl", syscall(__NR_prctl, option, arg2, arg3, arg4, arg5));
	int64_t errno_value = -errno;

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

	/* Parameter 1: res (type: PT_ERRNO)*/
	evt_test->assert_numeric_param(1, (uint64_t)errno_value);

	/* Parameter 2: option (type: PT_ENUMFLAGS32) */
	evt_test->assert_numeric_param(2, (int32_t)option);

	/* Parameter 3: arg2_str (type: PT_CHARBUF) */
	evt_test->assert_empty_param(3);

	/* Parameter 4: arg2_int (type: PT_INT64) */
	evt_test->assert_numeric_param(4, (int64_t)arg2);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);
}

TEST(SyscallExit, prctlX_get_child_subreaper)
{
	auto evt_test = get_syscall_event_test(__NR_prctl, EXIT_EVENT);

	// set the subreaper attribute
	assert_syscall_state(SYSCALL_SUCCESS, "prctl", syscall(__NR_prctl, PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0), EQUAL, 0);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int option = PR_GET_CHILD_SUBREAPER;
	int arg2 = 0;
	unsigned long arg3 = 0;
	unsigned long arg4 = 0;
	unsigned long arg5 = 0;

	assert_syscall_state(SYSCALL_SUCCESS, "prctl", syscall(__NR_prctl, option, &arg2, arg3, arg4, arg5), EQUAL, 0);


	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->disable_capture();

	// unset the subreaper attribute
	assert_syscall_state(SYSCALL_SUCCESS, "prctl", syscall(__NR_prctl, PR_SET_CHILD_SUBREAPER, 0, 0, 0, 0), EQUAL, 0);

	evt_test->assert_event_presence();

	if(HasFatalFailure())
	{
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO)*/
	evt_test->assert_numeric_param(1, (uint64_t)0);

	/* Parameter 2: option (type: PT_ENUMFLAGS32) */
	evt_test->assert_numeric_param(2, PPM_PR_GET_CHILD_SUBREAPER);

	/* Parameter 3: arg2_str (type: PT_CHARBUF) */
	evt_test->assert_empty_param(3);

	/* Parameter 4: arg2_int (type: PT_INT64) */
	evt_test->assert_numeric_param(4, (int64_t)1);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);
}

TEST(SyscallExit, prctlX_set_child_subreaper)
{
	auto evt_test = get_syscall_event_test(__NR_prctl, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int option = PR_SET_CHILD_SUBREAPER;
	unsigned long arg2 = 1337; /* This could be whatever value != 0, it is not a tid */
	unsigned long arg3 = 0;
	unsigned long arg4 = 0;
	unsigned long arg5 = 0;

	/* We need to use `SIGCHLD` otherwise the parent won't receive any signal
	 * when the child terminates.
	 */
	clone_args cl_args = {0};
	cl_args.exit_signal = SIGCHLD;

	pid_t ret_pid = syscall(__NR_clone3, &cl_args, sizeof(cl_args));
	if(ret_pid == 0)
	{
		/*
		 * Call the `prctl`
		 */
		assert_syscall_state(SYSCALL_SUCCESS, "prctl", syscall(__NR_prctl, option, arg2, arg3, arg4, arg5), EQUAL, 0);
		exit(EXIT_SUCCESS);
	}

	assert_syscall_state(SYSCALL_SUCCESS, "clone3", ret_pid, NOT_EQUAL, -1);

	/* Catch the child before doing anything else. */
	int status = 0;
	int options = 0;

	assert_syscall_state(SYSCALL_SUCCESS, "wait4", syscall(__NR_wait4, ret_pid, &status, options, NULL), NOT_EQUAL, -1);
	if(__WEXITSTATUS(status) == EXIT_FAILURE || __WIFSIGNALED(status) != 0)
	{
		FAIL() << "The prctl call is successful while it should fail..." << std::endl;
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

	/* Parameter 1: res (type: PT_ERRNO)*/
	evt_test->assert_numeric_param(1, (uint64_t)0);

	/* Parameter 2: option (type: PT_ENUMFLAGS32) */
	evt_test->assert_numeric_param(2, PPM_PR_SET_CHILD_SUBREAPER);

	/* Parameter 3: arg2_str (type: PT_CHARBUF) */
	evt_test->assert_empty_param(3);

	/* Parameter 4: arg2_int (type: PT_INT64) */
	evt_test->assert_numeric_param(4, (int64_t)arg2);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);
}

TEST(SyscallExit, prctlX_set_name)
{
	auto evt_test = get_syscall_event_test(__NR_prctl, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int option = PR_SET_NAME;
	const char arg2[] = "AAABAACAADAAEAAFAAGAAHAAIAAJAAKAALAAMAANAAOAAPAAQAARAASAATAAUAAVAAWAAXAAYAAZAAaAAbAAcAAdAAeAAfAAgAAhAAiAAjAAkAAlAAmAAnAAoAApAAqAArAAsAAtAAuAAvAAwAAxAAyAAzAA1AA2AA3AA4AA5AA6AA7AA8AA9AA0ABBABCABDABEABFABGABHABIABJABKABLABMABNABOABPABQABRABSABTABUABVABWABXAB";
	unsigned long arg3 = 0;
	unsigned long arg4 = 0;
	unsigned long arg5 = 0;

	/* We need to use `SIGCHLD` otherwise the parent won't receive any signal
	 * when the child terminates.
	 */
	clone_args cl_args = {0};
	cl_args.exit_signal = SIGCHLD;

	pid_t ret_pid = syscall(__NR_clone3, &cl_args, sizeof(cl_args));
	if(ret_pid == 0)
	{
		/*
		 * Call the `prctl`
		 */
		assert_syscall_state(SYSCALL_SUCCESS, "prctl", syscall(__NR_prctl, option, arg2, arg3, arg4, arg5), EQUAL, 0);
		exit(EXIT_SUCCESS);
	}

	assert_syscall_state(SYSCALL_SUCCESS, "clone3", ret_pid, NOT_EQUAL, -1);

	/* Catch the child before doing anything else. */

	int status = 0;
	int options = 0;

	assert_syscall_state(SYSCALL_SUCCESS, "wait4", syscall(__NR_wait4, ret_pid, &status, options, NULL), NOT_EQUAL, -1);
	if(__WEXITSTATUS(status) == EXIT_FAILURE || __WIFSIGNALED(status) != 0)
	{
		FAIL() << "The prctl call is successful while it should fail..." << std::endl;
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

	/* Parameter 1: res (type: PT_ERRNO)*/
	evt_test->assert_numeric_param(1, (uint64_t)0);

	/* Parameter 2: option (type: PT_ENUMFLAGS32) */
	evt_test->assert_numeric_param(2, PPM_PR_SET_NAME);

	/* Parameter 3: arg2_str (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(3, arg2);

	/* Parameter 4: arg2_int (type: PT_INT64) */
	evt_test->assert_numeric_param(4, (int64_t)0);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);
}
#endif

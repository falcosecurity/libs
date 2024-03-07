#include "../../event_class/event_class.h"
#include "../../helpers/proc_parsing.h"

#if defined(__NR_clone3) && defined(__NR_wait4)

#include <linux/sched.h>

TEST(GenericTracepoints, sched_switch)
{
	auto evt_test = get_generic_event_test(PPM_SC_SCHED_SWITCH);

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
		exit(EXIT_SUCCESS);
	}

	assert_syscall_state(SYSCALL_SUCCESS, "clone3", ret_pid, NOT_EQUAL, -1);
	/* Catch the child before doing anything else. */
	int status = 0;
	int options = 0;
	assert_syscall_state(SYSCALL_SUCCESS, "wait4", syscall(__NR_wait4, ret_pid, &status, options, NULL), NOT_EQUAL, -1);

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	/* We search for a father event. */
	evt_test->assert_event_presence();

	if(HasFatalFailure())
	{
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Here we cannot say which will be the next task pid, it could be the
	 * idle thread (pid=0) or the thread of the child, I have seen both
	 * cases while trying it, so probably the best thing here is to assert
	 * only that the pid must be a valid one, so `>=0`
	 */
	/* Parameter 1: next (type: PT_PID) */
	evt_test->assert_numeric_param(1, (int64_t)0, GREATER_EQUAL);

	/* Parameter 2: pgft_maj (type: PT_UINT64) */
	/* Right now we can't find a precise value to perform the assertion. */
	evt_test->assert_numeric_param(2, (int64_t)0, GREATER_EQUAL);

	/* Parameter 3: pgft_min (type: PT_UINT64) */
	/* Right now we can't find a precise value to perform the assertion. */
	evt_test->assert_numeric_param(3, (uint64_t)0, GREATER_EQUAL);

	/* Parameter 4: vm_size (type: PT_UINT32) */
	evt_test->assert_numeric_param(4, (uint32_t)0, GREATER_EQUAL);

	/* Parameter 5: vm_rss (type: PT_UINT32) */
	evt_test->assert_numeric_param(5, (uint32_t)0, GREATER_EQUAL);

	/* Parameter 6: vm_swap (type: PT_UINT32) */
	evt_test->assert_numeric_param(6, (uint32_t)0, GREATER_EQUAL);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(6);
}
#endif

#include "../../event_class/event_class.h"

#if defined(__NR_clone3) && defined(__NR_kill)

#include <signal.h>
#include <linux/sched.h>

TEST(GenericTracepoints, signal_deliver)
{
	auto evt_test = get_generic_event_test(PPM_SC_SIGNAL_DELIVER);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	struct clone_args cl_args = {0};
	cl_args.exit_signal = SIGCHLD;
	pid_t ret_pid = syscall(__NR_clone3, &cl_args, sizeof(cl_args));

	if(ret_pid == 0)
	{
		sleep(10);
		exit(EXIT_SUCCESS);
	}

	assert_syscall_state(SYSCALL_SUCCESS, "clone3", ret_pid, NOT_EQUAL, -1);

	/* Kill the child */
	assert_syscall_state(SYSCALL_SUCCESS, "kill", syscall(__NR_kill, ret_pid, SIGKILL), NOT_EQUAL, -1);
	
	/* Wait for the child to be killed */
	int status = 0;
	int options = 0;
	assert_syscall_state(SYSCALL_SUCCESS, "wait4", syscall(__NR_wait4, ret_pid, &status, options, NULL), NOT_EQUAL, -1);

	if(__WTERMSIG(status) != SIGKILL)
	{
		FAIL() << "The child is not killed by the signal." << std::endl;
	}

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence(ret_pid);

	if(HasFatalFailure())
	{
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: spid (type: PT_PID) */
	/* In this case we are not able to extract the sender pid */
	evt_test->assert_numeric_param(1, (int64_t)0);

	/* Parameter 2: dpid (type: PT_PID) */
	evt_test->assert_numeric_param(2, (int64_t)ret_pid);

	/* Parameter 3: sig (type: PT_SIGTYPE) */
	evt_test->assert_numeric_param(3, (uint8_t)SIGKILL);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}
#endif

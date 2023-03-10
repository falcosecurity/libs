#include "../../event_class/event_class.h"

#ifdef __NR_kill

#include <signal.h>

static void signal_deliver_callback(int signal)
{
}

TEST(GenericTracepoints, signal_deliver)
{
	auto evt_test = get_generic_event_test(PPM_SC_SIGNAL_DELIVER);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	if(signal(SIGUSR1, signal_deliver_callback) == SIG_ERR)
	{
		FAIL() << "An error occurred while setting SIGUSR1 signal handler.\n";
	}

	/* Send a signal to the caller */
	assert_syscall_state(SYSCALL_SUCCESS, "kill", syscall(__NR_kill, getpid(), SIGUSR1), NOT_EQUAL, -1);

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

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
	evt_test->assert_numeric_param(2, (int64_t)getpid());

	/* Parameter 3: sig (type: PT_SIGTYPE) */
	evt_test->assert_numeric_param(3, (uint8_t)SIGUSR1);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}
#endif

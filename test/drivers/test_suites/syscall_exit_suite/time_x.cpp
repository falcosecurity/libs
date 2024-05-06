
#include "../../event_class/event_class.h"

#ifdef __NR_time
TEST(SyscallExit, time_X)
{
	auto evt_test = get_syscall_event_test(__NR_time, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	syscall(__NR_time, NULL);

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Disable the capture: no more events from now. */
	evt_test->disable_capture();

	/* Retrieve events in order. */
	evt_test->assert_event_presence(CURRENT_PID, PPME_GENERIC_X);

	if(HasFatalFailure())
	{
		return;
	}

	evt_test->parse_event();
	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: ID (type: PT_SYSCALLID) */
	/* This is the PPM_SC code obtained from the syscall id. */
	evt_test->assert_numeric_param(1, (uint16_t)PPM_SC_TIME);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif

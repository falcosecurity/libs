#include "../../event_class/event_class.h"
#if defined(__NR_prctl)
TEST(SyscallEnter, prctlE)
{
	auto evt_test = get_syscall_event_test(__NR_prctl, ENTER_EVENT);
	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int option = -2;
	unsigned long arg2 = 0;
	unsigned long arg3 = 0;
	unsigned long arg4 = 0;
	unsigned long arg5 = 0;

	assert_syscall_state(SYSCALL_SUCCESS, "prctl", syscall(__NR_prctl, option, arg2, arg3, arg4, arg5));

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

	// Here we have no parameters to assert.

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(0);

}
#endif

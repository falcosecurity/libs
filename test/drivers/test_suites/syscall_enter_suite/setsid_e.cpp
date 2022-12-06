#include "../../event_class/event_class.h"

#ifdef __NR_setsid
TEST(SyscallEnter, setsidE)
{
	auto evt_test = get_syscall_event_test(__NR_setsid, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Here it depends on where we are running the test (the permissions we have) if
	 * the syscall will fail or not so we cannot assert it, we assert just the parameters.
	 */
	syscall(__NR_setsid);

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

	// Here we have no parameters to assert.

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(0);
}
#endif

#include "../../event_class/event_class.h"

#ifdef __NR_unlink
TEST(SyscallEnter, unlinkE)
{
	auto evt_test = get_syscall_event_test(__NR_unlink, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	const char* path = NULL;
	assert_syscall_state(SYSCALL_FAILURE, "unlink", syscall(__NR_unlink, path));

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

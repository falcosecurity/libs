#include "../../event_class/event_class.h"

#ifdef __NR_access

TEST(SyscallEnter, accessE)
{
	auto evt_test = get_syscall_event_test(__NR_access, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t _mode = W_OK;
	const char *_pathname = "./mock_file";
	assert_syscall_state(SYSCALL_FAILURE, "access", syscall(__NR_access, _pathname, _mode));

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure())
	{
		return;
	}

	evt_test->parse_event();

	//evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	// Here we have no parameters to assert.

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(0);
}
#endif

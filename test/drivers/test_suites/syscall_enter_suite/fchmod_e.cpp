#include "../../event_class/event_class.h"

#ifdef __NR_fchmod
TEST(SyscallEnter, fchmodE)
{
	auto evt_test = get_syscall_event_test(__NR_fchmod, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t mock_fd = -1;
	uint32_t mode = 0;
	assert_syscall_state(SYSCALL_FAILURE, "fchmod", syscall(__NR_fchmod, mock_fd, mode));

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

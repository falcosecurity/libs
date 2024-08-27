#include "../../event_class/event_class.h"

#ifdef __NR_getpeername
TEST(SyscallExit, getpeernameX)
{
	auto evt_test = get_syscall_event_test(__NR_getpeername, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t mock_fd = -1;
	void* usockaddr = NULL;
	int* usockaddr_len = NULL;
	assert_syscall_state(SYSCALL_FAILURE, "getpeername", syscall(__NR_getpeername, mock_fd, usockaddr, usockaddr_len));

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

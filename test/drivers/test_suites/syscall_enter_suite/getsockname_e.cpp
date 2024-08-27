#include "../../event_class/event_class.h"

#ifdef __NR_getsockname
TEST(SyscallEnter, getsocknameE)
{
	auto evt_test = get_syscall_event_test(__NR_getsockname, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t mock_fd = -1;
	void* usockaddr = NULL;
	int* usockaddr_len = NULL;
	assert_syscall_state(SYSCALL_FAILURE, "getsockname", syscall(__NR_getsockname, mock_fd, usockaddr, usockaddr_len));

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

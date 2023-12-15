#include "../../event_class/event_class.h"

#ifdef __NR_accept

TEST(SyscallEnter, acceptE)
{
	auto evt_test = get_syscall_event_test(__NR_accept, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t mock_fd = -1;
	sockaddr* addr = NULL;
	socklen_t *addrlen = NULL;
	assert_syscall_state(SYSCALL_FAILURE, "accept", syscall(__NR_accept, mock_fd, addr, addrlen));

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

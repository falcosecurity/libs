#include "../../event_class/event_class.h"

#ifdef __NR_bind
TEST(SyscallEnter, bindE)
{
	auto evt_test = get_syscall_event_test(__NR_bind, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t mock_fd = -1;
	sockaddr* addr = NULL;
	socklen_t addrlen = 0;
	assert_syscall_state(SYSCALL_FAILURE, "bind", syscall(__NR_bind, mock_fd, addr, addrlen));

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

	/* Parameter 1: fd (type: PT_FD) */
	evt_test->assert_numeric_param(1, (int64_t)mock_fd);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif

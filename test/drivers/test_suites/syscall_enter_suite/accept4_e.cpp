#include "../../event_class/event_class.h"

#ifdef __NR_accept4

TEST(SyscallEnter, accept4E)
{
	auto evt_test = get_syscall_event_test(__NR_accept4, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t mock_fd = -1;
	sockaddr* addr = NULL;
	socklen_t *addrlen = NULL;
	int flags = 0;
	assert_syscall_state(SYSCALL_FAILURE, "accept4", syscall(__NR_accept4, mock_fd, addr, addrlen, flags));

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

	/* Parameter 1: flags (type: PT_FLAGS32) */
	/* Right now `flags` are not supported so we will catch always `0` */
	evt_test->assert_numeric_param(1, (uint32_t)0);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif

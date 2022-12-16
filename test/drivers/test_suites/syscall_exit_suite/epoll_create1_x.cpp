#include "../../event_class/event_class.h"

#if defined(__NR_epoll_create1) && defined(__NR_close)
TEST(SyscallExit, epoll_create1X)
{
	auto evt_test = get_syscall_event_test(__NR_epoll_create1, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t flags = 0;
	int32_t fd = syscall(__NR_epoll_create1, flags);
	assert_syscall_state(SYSCALL_SUCCESS, "epoll_create1", fd, NOT_EQUAL, -1);
	syscall(__NR_close, fd);

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

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)fd);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif

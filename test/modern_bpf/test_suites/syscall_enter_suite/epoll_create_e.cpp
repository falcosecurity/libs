#include "../../event_class/event_class.h"

#if defined(__NR_epoll_create) && defined(__NR_close)
TEST(SyscallEnter, epoll_createE)
{
	auto evt_test = get_syscall_event_test(__NR_epoll_create, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t size = 1024;
	int32_t fd = syscall(__NR_epoll_create, size);
	assert_syscall_state(SYSCALL_SUCCESS, "epoll_create", fd, NOT_EQUAL, -1);
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

	/* Parameter 1: size (type: PT_INT32) */
	evt_test->assert_numeric_param(1, size);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif

#include "../../event_class/event_class.h"
#include <sys/epoll.h>

#if defined(__NR_epoll_create1) && defined(__NR_close)
TEST(SyscallEnter, epoll_create1E)
{
	auto evt_test = get_syscall_event_test(__NR_epoll_create1, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t flags = EPOLL_CLOEXEC;
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

	/* Parameter 1: flags (type: PT_FLAGS32) */
	evt_test->assert_numeric_param(1, PPM_EPOLL_CLOEXEC);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif

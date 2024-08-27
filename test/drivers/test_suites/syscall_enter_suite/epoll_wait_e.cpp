#include "../../event_class/event_class.h"

#ifdef __NR_epoll_wait
TEST(SyscallEnter, epoll_waitE)
{
	auto evt_test = get_syscall_event_test(__NR_epoll_wait, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t epfd = -1;
	void* events = NULL;
	int maxevents = 10;
	int timeout = 0;
	assert_syscall_state(SYSCALL_FAILURE, "epoll_wait", syscall(__NR_epoll_wait, epfd, events, maxevents, timeout));

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

	/* Parameter 1: maxevents (type: PT_ERRNO)*/
	evt_test->assert_numeric_param(1, (int64_t)maxevents);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif

#include "../../event_class/event_class.h"

#if defined(__NR_eventfd) && defined(__NR_close)
TEST(SyscallEnter, eventfdE)
{
	auto evt_test = new event_test(__NR_eventfd, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	uint32_t initval = 3;
	int flags = 0;
	int32_t fd = syscall(__NR_eventfd, initval, flags);
	assert_syscall_state(SYSCALL_SUCCESS, "eventfd", fd, NOT_EQUAL, -1);
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

	/* Parameter 1: initval (type: PT_UINT64) */
	evt_test->assert_numeric_param(1, (uint64_t)initval);

	/* Parameter 2: flags (type: PT_FLAGS32) */
	/* Right now we don't catch any flag, so we expect `0` as a second parameter. */
	evt_test->assert_numeric_param(2, (uint32_t)0);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}
#endif

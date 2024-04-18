#include "../../event_class/event_class.h"

#if defined(__NR_eventfd2)
TEST(SyscallEnter, eventfd2E)
{
	auto evt_test = get_syscall_event_test(__NR_eventfd2, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	uint32_t initval = 25;
	int flags = -1;
	assert_syscall_state(SYSCALL_FAILURE, "eventfd2", syscall(__NR_eventfd2, initval, flags));

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

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif

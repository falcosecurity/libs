#include "../../event_class/event_class.h"

#ifdef __NR_nanosleep
TEST(SyscallEnter, nanosleepE)
{
	auto evt_test = get_syscall_event_test(__NR_nanosleep, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	const struct timespec req = { .tv_sec = 0, .tv_nsec = 0 };
	struct timespec rem;
	int ret = syscall(__NR_nanosleep, &req, &rem);
	assert_syscall_state(SYSCALL_SUCCESS, "nanosleep", ret, NOT_EQUAL, -1);

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

	/* Parameter 1: interval (type: PT_RELTIME) */

	evt_test->assert_numeric_param(1, ((unsigned long)req.tv_sec) * 1000000000 + req.tv_nsec);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif

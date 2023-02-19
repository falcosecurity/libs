#include "../../event_class/event_class.h"

#ifdef __NR_nanosleep

TEST(SyscallExit, nanosleepX)
{
	auto evt_test = get_syscall_event_test(__NR_nanosleep, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	struct timespec req = { .tv_sec = 0, .tv_nsec = 1 };
	struct timespec rem;
	int interval = syscall(__NR_nanosleep, &req, &rem);
	assert_syscall_state(SYSCALL_SUCCESS, "nanosleep", interval, NOT_EQUAL, -1);

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
	evt_test->assert_numeric_param(1, (int64_t)0);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif

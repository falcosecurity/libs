#include "../../event_class/event_class.h"

#ifdef __NR_setrlimit

#include <sys/resource.h>

TEST(SyscallExit, setrlimitX)
{
	auto evt_test = get_syscall_event_test(__NR_setrlimit, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int resource = -1;
	struct rlimit rlim;
	rlim.rlim_cur = 50;
	rlim.rlim_max = 10020;
	assert_syscall_state(SYSCALL_FAILURE, "setrlimit", syscall(__NR_setrlimit, resource, &rlim));
	int64_t errno_value = -errno;

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
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/* Parameter 2: cur (type: PT_INT64) */
	evt_test->assert_numeric_param(2, (int64_t)rlim.rlim_cur);

	/* Parameter 3: max (type: PT_INT64) */
	evt_test->assert_numeric_param(3, (int64_t)rlim.rlim_max);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}
#endif

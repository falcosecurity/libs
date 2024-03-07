#include "../../event_class/event_class.h"

#ifdef __NR_fstat
TEST(SyscallExit, fstatX)
{
	auto evt_test = get_syscall_event_test(__NR_fstat, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int f_desc = -1;
	struct stat statbuf = {};
	assert_syscall_state(SYSCALL_FAILURE, "fstat", syscall(__NR_fstat, f_desc, &statbuf));
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

	/* Parameter 1: res (type: PT_ERRNO)*/
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif

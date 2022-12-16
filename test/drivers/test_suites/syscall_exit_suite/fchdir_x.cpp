#include "../../event_class/event_class.h"

#ifdef __NR_fchdir
TEST(SyscallExit, fchdirX)
{
	auto evt_test = get_syscall_event_test(__NR_fchdir, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int invalid_fd = -1;
	assert_syscall_state(SYSCALL_FAILURE, "fchdir", syscall(__NR_fchdir, invalid_fd));
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
	evt_test->assert_numeric_param(1, errno_value);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif

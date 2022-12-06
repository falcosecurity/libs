#include "../../event_class/event_class.h"

#ifdef __NR_close
TEST(SyscallExit, closeX)
{
	auto evt_test = get_syscall_event_test(__NR_close, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int invalid_fd = -1;
	assert_syscall_state(SYSCALL_FAILURE, "close", syscall(__NR_close, invalid_fd));
	int64_t errno_value = -errno;

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

	/* Parameter 1: ret (type: PT_ERRNO)*/
	evt_test->assert_numeric_param(1, errno_value);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif

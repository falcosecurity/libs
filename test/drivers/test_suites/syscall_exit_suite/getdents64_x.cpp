#include "../../event_class/event_class.h"

#ifdef __NR_getdents64
TEST(SyscallExit, getdents64X)
{
	auto evt_test = get_syscall_event_test(__NR_getdents64, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t invalid_fd = 10;
	void* dirp = NULL;
	int count = 0;
	assert_syscall_state(SYSCALL_FAILURE, "getdents64", syscall(__NR_getdents64, invalid_fd, dirp, count));
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

	/* Parameter 1: fd (type: PT_FD) */
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif

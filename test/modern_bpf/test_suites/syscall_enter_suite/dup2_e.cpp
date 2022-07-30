#include "../../event_class/event_class.h"

#if defined(__NR_dup2) && defined(__NR_openat) && defined(__NR_close)
TEST(SyscallEnter, dup2E)
{
	auto evt_test = new event_test(__NR_dup2, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t old_fd = syscall(__NR_openat, AT_FDCWD, ".", O_RDWR | O_TMPFILE, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "openat", old_fd, NOT_EQUAL, -1);

	int32_t new_fd = old_fd;
	int32_t res = syscall(__NR_dup2, old_fd, new_fd);
	assert_syscall_state(SYSCALL_SUCCESS, "dup2", res, NOT_EQUAL, -1);

	syscall(__NR_close, old_fd);
	syscall(__NR_close, new_fd);
	syscall(__NR_close, res);

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

	/* Parameter 1: fd (type: PT_FD) */
	evt_test->assert_numeric_param(1, (int64_t)old_fd);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif

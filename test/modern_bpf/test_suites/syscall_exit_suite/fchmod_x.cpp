#include "../../event_class/event_class.h"

#ifdef __NR_fchmod
TEST(SyscallExit, fchmodX)
{
	auto evt_test = new event_test(__NR_fchmod, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t mock_fd = -1;
	uint32_t mode = S_IXUSR;
	assert_syscall_state(SYSCALL_FAILURE, "fchmod", syscall(__NR_fchmod, mock_fd, mode));
	int32_t errno_value = -errno;

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

	/* Parameter 1: res (type: PT_ERRNO32) */
	evt_test->assert_numeric_param(1, errno_value);

	/* Parameter 2: fd (type: PT_FD32) */
	evt_test->assert_numeric_param(2, mock_fd);

	/* Parameter 3: mode (type: PT_MODE) */
	evt_test->assert_numeric_param(3, (uint32_t)PPM_S_IXUSR);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}
#endif

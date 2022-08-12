#include "../../event_class/event_class.h"

#ifdef __NR_ioctl

#include <sys/ioctl.h>

TEST(SyscallEnter, ioctlE)
{
	auto evt_test = new event_test(__NR_ioctl, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	/* The `fd` must be an open file descriptor. In this case, we pass an invalid
	 * file descriptor so the call will fail.
	 */
	int32_t mock_fd = -1;
	uint64_t request = SIOCGIFCOUNT;
	char* argp = NULL;
	assert_syscall_state(SYSCALL_FAILURE, "ioctl", syscall(__NR_ioctl, mock_fd, request, argp));

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
	evt_test->assert_numeric_param(1, (int64_t)mock_fd);

	/* Parameter 2: request (type: PT_UINT64) */
	evt_test->assert_numeric_param(2, (uint64_t)request);

	/* Parameter 3: argument (type: PT_UINT64) */
	evt_test->assert_numeric_param(3, (uint64_t)0);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}
#endif

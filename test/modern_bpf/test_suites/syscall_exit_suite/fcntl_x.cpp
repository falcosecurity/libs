#include "../../event_class/event_class.h"

#ifdef __NR_fcntl

#include <fcntl.h>

TEST(SyscallExit, fcntlX)
{
	auto evt_test = new event_test(__NR_fcntl, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t invalid_fd = -1;
	int cmd = F_DUPFD_CLOEXEC;
	assert_syscall_state(SYSCALL_FAILURE, "fcntl", syscall(__NR_fcntl, invalid_fd, cmd));
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

	/* Parameter 1: ret (type: PT_FD)*/
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif

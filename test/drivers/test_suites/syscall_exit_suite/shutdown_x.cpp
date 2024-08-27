#include "../../event_class/event_class.h"

#ifdef __NR_shutdown

#include <sys/socket.h>

TEST(SyscallExit, shutdownX)
{
	auto evt_test = get_syscall_event_test(__NR_shutdown, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t invalid_fd = -1;
	int how = SHUT_RD;
	assert_syscall_state(SYSCALL_FAILURE, "shutdown", syscall(__NR_shutdown, invalid_fd, how));
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

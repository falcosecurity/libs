#include "../../event_class/event_class.h"

#ifdef __NR_shutdown

#include <sys/socket.h>

TEST(SyscallEnter, shutdownE)
{
	auto evt_test = get_syscall_event_test(__NR_shutdown, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t invalid_fd = -1;
	int how = SHUT_RD;
	assert_syscall_state(SYSCALL_FAILURE, "shutdown", syscall(__NR_shutdown, invalid_fd, how));

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
	evt_test->assert_numeric_param(1, (int64_t)invalid_fd);

	/* Parameter 2: how (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(2, (uint8_t)PPM_SHUT_RD);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}
#endif

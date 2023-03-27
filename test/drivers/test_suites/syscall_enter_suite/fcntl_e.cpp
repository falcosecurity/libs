#include "../../event_class/event_class.h"

#ifdef __NR_fcntl

#include <fcntl.h>

TEST(SyscallEnter, fcntlE)
{
	auto evt_test = get_syscall_event_test(__NR_fcntl, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* If the dropping logic is not enabled we should be always able to collect this event */
	int32_t invalid_fd = -1;
	int cmd = F_NOTIFY;
	assert_syscall_state(SYSCALL_FAILURE, "fcntl", syscall(__NR_fcntl, invalid_fd, cmd));

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

	/* Parameter 2: cmd (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(2, (uint8_t)PPM_FCNTL_F_NOTIFY);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}
#endif

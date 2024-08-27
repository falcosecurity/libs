#include "../../event_class/event_class.h"

#ifdef __NR_setpgid
TEST(SyscallExit, setpgidX)
{
	auto evt_test = get_syscall_event_test(__NR_setpgid, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	pid_t pid = -1;
	pid_t pgid = -2;
	assert_syscall_state(SYSCALL_FAILURE, "setpgid", syscall(__NR_setpgid, pid, pgid));
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

	/* Parameter 1: res (type: PT_PID) */
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif

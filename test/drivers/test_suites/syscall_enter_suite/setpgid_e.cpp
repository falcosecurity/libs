#include "../../event_class/event_class.h"

#ifdef __NR_setpgid
TEST(SyscallEnter, setpgidE)
{
	auto evt_test = get_syscall_event_test(__NR_setpgid, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	pid_t pid = -1;
	pid_t pgid = -2;
	assert_syscall_state(SYSCALL_FAILURE, "setpgid", syscall(__NR_setpgid, pid, pgid));

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

	/* Parameter 1: pid (type: PT_FD) */
	evt_test->assert_numeric_param(1, (int64_t)pid);

	/* Parameter 2: pgid (type: PT_PID) */
	evt_test->assert_numeric_param(2, (int64_t)pgid);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}
#endif

#include "../../event_class/event_class.h"

#ifdef __NR_setgid
TEST(SyscallExit, setgidX)
{
	auto evt_test = get_syscall_event_test(__NR_setgid, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	gid_t gid = (uint32_t)-1;
	assert_syscall_state(SYSCALL_FAILURE, "setgid", syscall(__NR_setgid, gid));
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

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif

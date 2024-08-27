#include "../../event_class/event_class.h"

#ifdef __NR_getegid
TEST(SyscallExit, getegidX)
{
	auto evt_test = get_syscall_event_test(__NR_getegid, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	gid_t egid = syscall(__NR_getegid);
	assert_syscall_state(SYSCALL_SUCCESS, "getegid", egid, NOT_EQUAL, -1);

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

	/* Parameter 1: egid (type: PT_GID) */
	evt_test->assert_numeric_param(1, (uint32_t)egid);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif

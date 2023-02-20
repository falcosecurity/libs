#include "../../event_class/event_class.h"

#ifdef __NR_getresgid
TEST(SyscallEnter, getresgidE)
{
	auto evt_test = get_syscall_event_test(__NR_getresgid, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	gid_t rgid;
	gid_t egid;
	gid_t sgid;
	assert_syscall_state(SYSCALL_SUCCESS, "getresgid", syscall(__NR_getresgid, &rgid, &egid, &sgid), NOT_EQUAL, -1);

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

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(0);
}
#endif

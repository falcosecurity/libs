#include "../../event_class/event_class.h"

#ifdef __NR_getresuid
TEST(SyscallEnter, getresuidE)
{
	auto evt_test = get_syscall_event_test(__NR_getresuid, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	uid_t ruid;
	uid_t euid;
	uid_t suid;
	assert_syscall_state(SYSCALL_SUCCESS, "getresuid", syscall(__NR_getresuid, &ruid, &euid, &suid), NOT_EQUAL, -1);

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

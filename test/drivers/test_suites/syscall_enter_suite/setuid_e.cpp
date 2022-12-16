#include "../../event_class/event_class.h"

#ifdef __NR_setuid
TEST(SyscallEnter, setuidE)
{
	auto evt_test = get_syscall_event_test(__NR_setuid, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	uid_t uid = (uint32_t)-1;
	assert_syscall_state(SYSCALL_FAILURE, "setuid", syscall(__NR_setuid, uid));

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

	/* Parameter 1: uid (type: PT_UID) */
	evt_test->assert_numeric_param(1, (uint32_t)uid);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif

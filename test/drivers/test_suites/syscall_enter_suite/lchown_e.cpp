#include "../../event_class/event_class.h"

#ifdef __NR_lchown
TEST(SyscallEnter, lchownE)
{
	auto evt_test = get_syscall_event_test(__NR_lchown, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	assert_syscall_state(SYSCALL_FAILURE, "lchown", syscall(__NR_lchown, NULL, 0, 0));

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

	// Here we have no parameters to assert.

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(0);
}
#endif

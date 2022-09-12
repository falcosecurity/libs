#include "../../event_class/event_class.h"

#ifdef __NR_mkdir
TEST(SyscallEnter, mkdirE)
{
	auto evt_test = get_syscall_event_test(__NR_mkdir, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* This is a mock mode just to check that the value is correctly caught.
	 * The syscall should fail!
	 */
	uint32_t mode = 7;
	const char* path = NULL;
	assert_syscall_state(SYSCALL_FAILURE, "mkdir", syscall(__NR_mkdir, path, mode));

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

	/* Parameter 1: mode (type: PT_UINT32) */
	evt_test->assert_numeric_param(1, mode);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif

#include "../../event_class/event_class.h"

#ifdef __NR_chdir
TEST(SyscallEnter, chdirE)
{
	auto evt_test = get_syscall_event_test(__NR_chdir, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Syscall special notes:
	 * `chdir()` changes the current working directory of the calling
	 * process to the directory specified in path. Here we pass a mock dir
	 * so the call must fail.
	 */

	const char* new_dir = "mock_dir";
	assert_syscall_state(SYSCALL_FAILURE, "chdir", syscall(__NR_chdir, new_dir));

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

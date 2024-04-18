#include "../../event_class/event_class.h"

#if defined(__NR_inotify_init1)
TEST(SyscallEnter, inotify_init1E_failure)
{
	auto evt_test = get_syscall_event_test(__NR_inotify_init1, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	/* `flags = 15` is an invalid value so the syscall will return `EINVAL` as errno. */
	int32_t flags = 15;
	assert_syscall_state(SYSCALL_FAILURE, "inotify_init1", syscall(__NR_inotify_init1, flags));

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

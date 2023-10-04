#include "../../event_class/event_class.h"

#if defined(__NR_inotify_init) && defined(__NR_close)
TEST(SyscallEnter, inotify_initE)
{

	auto evt_test = get_syscall_event_test(__NR_inotify_init, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t fd = syscall(__NR_inotify_init);
	assert_syscall_state(SYSCALL_SUCCESS, "inotify_init", fd, NOT_EQUAL, -1);
	syscall(__NR_close, fd);

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

#include "../../event_class/event_class.h"

#ifdef __NR_userfaultfd
TEST(SyscallEnter, userfaultfdE)
{
	auto evt_test = get_syscall_event_test(__NR_userfaultfd, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	/* `flags = 3` is an invalid flag value so the syscall will return `EINVAL` as errno. */
	int flags = 3;
	assert_syscall_state(SYSCALL_FAILURE, "userfaultfd", syscall(__NR_userfaultfd, flags));

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

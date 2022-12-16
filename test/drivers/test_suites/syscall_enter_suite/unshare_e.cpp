#include "../../event_class/event_class.h"

#ifdef __NR_unshare

#include <sched.h>

TEST(SyscallEnter, unshareE)
{
	auto evt_test = get_syscall_event_test(__NR_unshare, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* If `flags` is specified as zero, then unshare() is a no-op.
	 * Here we want only the test that the correct event is sent not the value of the flags,
	 * call unshare with some flags can alter the state of the actual process and here
	 * we want to be as clear as possible, without changing namespace or something else.
	 */
	int flags = 0;
	assert_syscall_state(SYSCALL_SUCCESS, "unshare", syscall(__NR_unshare, flags), NOT_EQUAL, -1);

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure())
	{
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: flags (type: PT_FLAGS32) */
	evt_test->assert_numeric_param(1, (uint32_t)0);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif

#include "../../event_class/event_class.h"

#ifdef __NR_setsid
TEST(SyscallExit, setsidX)
{
	auto evt_test = get_syscall_event_test(__NR_setsid, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Here it depends on where we are running the test (the permissions we have) if
	 * the syscall will fail or not so we cannot assert it, we assert just the parameters.
	 */

	/* In case of failure the syscall returns `-EPERM` so `-errno` */
	pid_t new_session_id = syscall(__NR_setsid);

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

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)new_session_id);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif

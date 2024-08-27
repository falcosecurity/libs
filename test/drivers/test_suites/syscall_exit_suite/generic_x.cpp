#include "../../event_class/event_class.h"

#ifdef __NR_uname
TEST(SyscallExit, genericX)
{
	/* We use `uname` syscall because it is defined on all architectures
	 * and is a very simple syscall.
	 */
	auto evt_test = get_syscall_event_test(__NR_uname, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	assert_syscall_state(SYSCALL_FAILURE, "uname", syscall(__NR_uname, NULL));

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

	/* Parameter 1: ID (type: PT_SYSCALLID) */
	/* this is the PPM_SC code obtained from the syscall id. */
	evt_test->assert_numeric_param(1, (int16_t)PPM_SC_UNAME);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif

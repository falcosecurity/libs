#include "../../event_class/event_class.h"

#ifdef __NR_uname
TEST(SyscallEnter, genericE)
{
	/* We use `uname` syscall because it is defined on all architectures
	 * and is a very simple syscall.
	 */
	auto evt_test = get_syscall_event_test(__NR_uname, ENTER_EVENT);

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
	evt_test->assert_numeric_param(1, (uint16_t)PPM_SC_UNAME);

	/* Parameter 2: nativeID (type: PT_UINT16) */
	evt_test->assert_numeric_param(2, (uint16_t)__NR_uname);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}
#endif

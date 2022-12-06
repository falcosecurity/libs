#include "../../event_class/event_class.h"

#ifdef __NR_setns
TEST(SyscallEnter, setnsE)
{
	auto evt_test = get_syscall_event_test(__NR_setns, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int ns_fd = -1;
	int ns_type = CLONE_NEWCGROUP;
	assert_syscall_state(SYSCALL_FAILURE, "setns", syscall(__NR_setns, ns_fd, ns_type));

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

	/* Parameter 1: fd (type: PT_FD) */
	evt_test->assert_numeric_param(1, (int64_t)ns_fd);

	/* Parameter 2: nstype (type: PT_FLAGS32) */
	evt_test->assert_numeric_param(2, (uint32_t)PPM_CL_CLONE_NEWCGROUP);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}
#endif

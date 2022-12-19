#include "../../event_class/event_class.h"

#ifdef __NR_access

TEST(SyscallEnter, accessE)
{
	auto evt_test = get_syscall_event_test(__NR_access, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t mode = W_OK;
	char pathname[] = "//**null-file-path**//";
	assert_syscall_state(SYSCALL_FAILURE, "access", syscall(__NR_access, pathname, mode));

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

	/* Parameter 1: mode (type: PT_UINT32)*/
	evt_test->assert_numeric_param(1, (uint32_t)PPM_W_OK);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif

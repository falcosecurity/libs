#include "../../event_class/event_class.h"

#ifdef __NR_creat
TEST(SyscallEnter, creatE)
{
	auto evt_test = get_syscall_event_test(__NR_creat, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	const char* path = "*//null";
	mode_t mode = S_IRGRP;
	assert_syscall_state(SYSCALL_FAILURE, "creat", syscall(__NR_creat, path, mode));

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

	/* Parameter 1: name (type: PT_FSPATH) */
	evt_test->assert_charbuf_param(1, path);

	/* Parameter 2: mode (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (uint32_t)PPM_S_IRGRP);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}
#endif

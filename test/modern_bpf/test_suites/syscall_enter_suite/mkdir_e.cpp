#include "../../event_class/event_class.h"

#ifdef __NR_mkdir
TEST(SyscallEnter, mkdirE)
{
	auto evt_test = new event_test(PPME_SYSCALL_MKDIR_2_E);

	evt_test->mark_single_64bit_syscall_as_interesting(__NR_mkdir);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* This is a mock mode just to check that the value is correctly caught. 
	 * The syscall should fail!
	 */
	uint32_t mode = 7;
	const char* path = NULL;
	evt_test->assert_syscall_failure(syscall(__NR_mkdir, path, mode), "mkdir");

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* 1° Parameter: mode (type: PT_UINT32) */
	evt_test->assert_u32_param(1, mode);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif
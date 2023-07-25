#include "../../event_class/event_class.h"
#if defined(__NR_init_module)
TEST(SyscallEnter, init_moduleE)
{
	auto evt_test = get_syscall_event_test(__NR_init_module, ENTER_EVENT);
	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	char mock_img[100];
	unsigned long len = 100;
	char mock_buf[8];

	assert_syscall_state(SYSCALL_FAILURE, "init_module", syscall(__NR_init_module, (void *)(mock_img), len, (void *)(mock_buf)));


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

	// Here we have no parameters to assert.

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(0);

}
#endif

#include "../../event_class/event_class.h"
#if defined(__NR_finit_module)
TEST(SyscallEnter, finit_moduleE)
{
	auto evt_test = get_syscall_event_test(__NR_finit_module, ENTER_EVENT);
	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int mock_fd = -1;
	char mock_buf[8];
	int mock_flags = 0;

	assert_syscall_state(SYSCALL_FAILURE, "finit_module", syscall(__NR_finit_module, mock_fd, (void *)(mock_buf), mock_flags));


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

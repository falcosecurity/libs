#include "../../event_class/event_class.h"
#if defined(__NR_mknodat)
TEST(SyscallEnter, mknodatE_failure)
{
	auto evt_test = get_syscall_event_test(__NR_mknodat, ENTER_EVENT);
	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int mock_fd = -1;
	char mock_buf[100];

	assert_syscall_state(SYSCALL_FAILURE, "mknodat", syscall(__NR_mknodat, mock_fd, (void *)(mock_buf), NULL, 0));


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

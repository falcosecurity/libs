#include "../../event_class/event_class.h"

#ifdef __NR_pipe2
TEST(SyscallEnter, pipe2E)
{
	auto evt_test = get_syscall_event_test(__NR_pipe2, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t* pipefd = NULL;
	int flags = 0;
	assert_syscall_state(SYSCALL_FAILURE, "pipe2", syscall(__NR_pipe2, pipefd, flags));

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

	// Here we have no parameters to assert.

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(0);
}
#endif

#include "../../event_class/event_class.h"

#ifdef __NR_sendmmsg
TEST(SyscallEnter, sendmmsgE)
{
	auto evt_test = get_syscall_event_test(__NR_sendmmsg, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t mock_fd = -1;
	struct msghdr *msg = NULL;
	uint32_t vlen = 0;
	int flags = 0;
	assert_syscall_state(SYSCALL_FAILURE, "sendmmsg", syscall(__NR_sendmmsg, mock_fd, msg, vlen, flags));

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

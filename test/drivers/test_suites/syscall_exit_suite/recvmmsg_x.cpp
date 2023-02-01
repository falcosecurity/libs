#include "../../event_class/event_class.h"

#ifdef __NR_recvmmsg
TEST(SyscallExit, recvmmsgX)
{
	auto evt_test = get_syscall_event_test(__NR_recvmmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t mock_fd = -1;
	struct msghdr *msg = NULL;
	uint32_t vlen = 0;
	int flags = 0;
	struct timespec *timeout = NULL;
	assert_syscall_state(SYSCALL_FAILURE, "recvmmsg", syscall(__NR_recvmmsg, mock_fd, msg, vlen, flags, timeout));

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

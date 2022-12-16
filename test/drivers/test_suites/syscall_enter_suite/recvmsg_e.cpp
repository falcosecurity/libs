#include "../../event_class/event_class.h"

#ifdef __NR_recvmsg
TEST(SyscallEnter, recvmsgE)
{
	auto evt_test = get_syscall_event_test(__NR_recvmsg, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t mock_fd = -1;
	struct msghdr *msg = NULL;
	int flags = 0;
	assert_syscall_state(SYSCALL_FAILURE, "recvmsg", syscall(__NR_recvmsg, mock_fd, msg, flags));

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

	/* Parameter 1: fd (type: PT_FD) */
	evt_test->assert_numeric_param(1, (int64_t)mock_fd);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif

#include "../../event_class/event_class.h"

#ifdef __NR_splice

TEST(SyscallExit, spliceX)
{
	auto evt_test = get_syscall_event_test(__NR_splice, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int fd_in = 1;
	int fd_out = 1;
	uint64_t size = 0x123;
	unsigned int flags = SPLICE_F_MOVE;
	assert_syscall_state(SYSCALL_FAILURE, "splice", syscall(__NR_splice, fd_in, 0, fd_out, 0, size, flags));
	int64_t errno_value = -errno;

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

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif
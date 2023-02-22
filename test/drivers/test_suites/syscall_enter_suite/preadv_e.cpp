#include "../../event_class/event_class.h"

#ifdef __NR_preadv

TEST(SyscallEnter, preadvE)
{
	auto evt_test = get_syscall_event_test(__NR_preadv, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t fd = -1;
	int32_t iovcnt = 7;
	off_t pos = 13;
	assert_syscall_state(SYSCALL_FAILURE, "preadv", syscall(__NR_preadv, fd, nullptr, iovcnt, pos));

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

	/* Parameter 1: fd (type: PT_FD) */
	evt_test->assert_numeric_param(1, (int64_t)fd);

	/* Parameter 2: pos (type: PT_UINT64) */
	evt_test->assert_numeric_param(2, (uint64_t)pos);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}
#endif

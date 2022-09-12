#include "../../event_class/event_class.h"

#ifdef __NR_tkill
TEST(SyscallExit, tkillX)
{
	auto evt_test = get_syscall_event_test(__NR_tkill, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	/* `mock_tid==0` is an invalid value so the syscall will fail with `EINVAL`. */
	int32_t mock_tid = 0;
	int32_t signal = 0;
	assert_syscall_state(SYSCALL_FAILURE, "tkill", syscall(__NR_tkill, mock_tid, signal));
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
	evt_test->assert_numeric_param(1, errno_value);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif

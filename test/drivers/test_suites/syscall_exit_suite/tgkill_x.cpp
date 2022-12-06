#include "../../event_class/event_class.h"

#ifdef __NR_tgkill
TEST(SyscallExit, tgkillX)
{
	auto evt_test = get_syscall_event_test(__NR_tgkill, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	/* `mock_tgid==0` and `mock_tid==0` are invalid values so the syscall will
	 * fail with `EINVAL`.
	 */
	int32_t mock_tgid = 0;
	int32_t mock_tid = 0;
	int32_t signal = 0;
	assert_syscall_state(SYSCALL_FAILURE, "tgkill", syscall(__NR_tgkill, mock_tgid, mock_tid, signal));
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

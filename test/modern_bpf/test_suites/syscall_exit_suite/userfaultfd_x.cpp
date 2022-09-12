#include "../../event_class/event_class.h"

#ifdef __NR_userfaultfd
TEST(SyscallExit, userfaultfdX)
{
	auto evt_test = get_syscall_event_test(__NR_userfaultfd, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	/* `flags = 3` is an invalid flag value so the syscall will return `EINVAL` as errno. */
	int flags = 3;
	assert_syscall_state(SYSCALL_FAILURE, "userfaultfd", syscall(__NR_userfaultfd, flags));
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

	/* Parameter 1: res (type: PT_FD) */
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/* Parameter 2: flags (type: PT_FLAGS32) */
	evt_test->assert_numeric_param(2, (uint32_t)flags);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}
#endif

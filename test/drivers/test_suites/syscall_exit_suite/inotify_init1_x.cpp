#include "../../event_class/event_class.h"

#if defined(__NR_inotify_init1) && defined(__NR_close)
#include <sys/inotify.h>
TEST(SyscallExit, inotify_init1X_success)
{
	auto evt_test = get_syscall_event_test(__NR_inotify_init1, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	/* Our instrumentation will convert these into `O_NONBLOCK | O_CLOEXEC` */
	int32_t flags = IN_NONBLOCK | IN_CLOEXEC;
	int32_t fd = syscall(__NR_inotify_init1, flags);
	assert_syscall_state(SYSCALL_SUCCESS, "inotify_init1", fd, NOT_EQUAL, -1);
	syscall(__NR_close, fd);

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

	/* Parameter 2: flags (type: PT_FLAGS16) */
	/* The `inotify_init1` flags are converted into the open ones */
	evt_test->assert_numeric_param(2, (uint16_t)(PPM_O_NONBLOCK | PPM_O_CLOEXEC));

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

TEST(SyscallExit, inotify_init1X_failure)
{
	auto evt_test = get_syscall_event_test(__NR_inotify_init1, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	/* `flags = 15` is an invalid value so the syscall will return `EINVAL` as errno. */
	int32_t flags = 15;
	assert_syscall_state(SYSCALL_FAILURE, "inotify_init1", syscall(__NR_inotify_init1, flags));
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

	/* Parameter 1: fd (type: PT_FD) */
	evt_test->assert_numeric_param(1, errno_value);

	/* Parameter 2: flags (type: PT_FLAGS16) */
	/* if the driver is not able to recognize any known flag it returns `0` */
	evt_test->assert_numeric_param(2, (uint16_t)0);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}
#endif

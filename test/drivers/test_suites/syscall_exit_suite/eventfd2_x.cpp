#include "../../event_class/event_class.h"

#if defined(__NR_eventfd2) && defined(__NR_close)
#include <sys/eventfd.h>
TEST(SyscallExit, eventfd2X_success)
{
	auto evt_test = get_syscall_event_test(__NR_eventfd2, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	uint32_t initval = 3;
	/* Our instrumentation will convert these into `O_NONBLOCK | O_CLOEXEC` */
	int32_t flags = EFD_NONBLOCK | EFD_CLOEXEC;
	int32_t fd = syscall(__NR_eventfd2, initval, flags);
	assert_syscall_state(SYSCALL_SUCCESS, "eventfd2", fd, NOT_EQUAL, -1);
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

	/* Parameter 1: res (type: PT_FD) */
	evt_test->assert_numeric_param(1, (int64_t)fd);

	/* Parameter 2: flags (type: PT_FLAGS16) */
	evt_test->assert_numeric_param(2, (uint16_t)(PPM_O_NONBLOCK | PPM_O_CLOEXEC));

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

TEST(SyscallExit, eventfd2X_failure)
{
	auto evt_test = get_syscall_event_test(__NR_eventfd2, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	uint32_t initval = 25;
	int flags = -1;
	assert_syscall_state(SYSCALL_FAILURE, "eventfd2", syscall(__NR_eventfd2, initval, flags));
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

	/* Parameter 2: flags (type: PT_FLAGS16) */
	/* if the driver is not able to recognize any known flag it returns `0` */
	evt_test->assert_numeric_param(2, (uint16_t)0);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}
#endif

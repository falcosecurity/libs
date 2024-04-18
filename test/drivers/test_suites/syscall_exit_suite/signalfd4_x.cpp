#include "../../event_class/event_class.h"

#ifdef __NR_signalfd4

#include <sys/signalfd.h>

TEST(SyscallExit, signalfd4X)
{
	auto evt_test = get_syscall_event_test(__NR_signalfd4, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	/* `mask` and `flags` are not catched BPF side. */
	int32_t mock_fd = -1;
	sigset_t mask = {0};
	size_t sizemask = 0;
	/* Our instrumentation will convert these into `O_NONBLOCK | O_CLOEXEC` */
	int flags = SFD_NONBLOCK | SFD_CLOEXEC;
	assert_syscall_state(SYSCALL_FAILURE, "signalfd4", syscall(__NR_signalfd4, mock_fd, &mask, sizemask, flags));
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

	/* Parameter 1: res (type: PT_ERRNO)*/
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/* Parameter 2: flags (type: PT_FLAGS16) */
	evt_test->assert_numeric_param(2, (uint16_t)(PPM_O_NONBLOCK | PPM_O_CLOEXEC));

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}
#endif

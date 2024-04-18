#include "../../event_class/event_class.h"

#ifdef __NR_signalfd

#include <sys/signalfd.h>

TEST(SyscallExit, signalfdX)
{
	auto evt_test = get_syscall_event_test(__NR_signalfd, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	/* `mask` is not caught BPF side. */
	int32_t mock_fd = -1;
	sigset_t mask = {0};
	size_t sizemask = 0;
	assert_syscall_state(SYSCALL_FAILURE, "signalfd", syscall(__NR_signalfd, mock_fd, &mask, sizemask));
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

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif

#include "../../event_class/event_class.h"

#ifdef __NR_signalfd

#include <sys/signalfd.h>

TEST(SyscallEnter, signalfdE)
{
	auto evt_test = get_syscall_event_test(__NR_signalfd, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	/* `mask` is not caught BPF side. */
	int32_t mock_fd = -1;
	sigset_t mask = {0};
	size_t sizemask = 0;
	assert_syscall_state(SYSCALL_FAILURE, "signalfd", syscall(__NR_signalfd, mock_fd, &mask, sizemask));

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
	evt_test->assert_numeric_param(1, (int64_t)mock_fd);

	/* Parameter 2: mask (type: PT_UINT32) */
	/* Right now we don't catch any mask, so we expect `0` as a second parameter. */
	evt_test->assert_numeric_param(2, (uint32_t)0);

	/* Parameter 3: flags (type: PT_FLAGS8) */
	evt_test->assert_numeric_param(3, (uint8_t)0);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}
#endif

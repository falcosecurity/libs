#include "../../event_class/event_class.h"

#ifdef __NR_signalfd4

#include <sys/signalfd.h>

TEST(SyscallEnter, signalfd4E)
{

	/* Please note:
	 * the syscall `signalfd4` is mapped to `PPME_SYSCALL_SIGNALFD_E` event
	 * like `signalfd`. The same BPF program will be used for both the syscalls.
	 */

	auto evt_test = get_syscall_event_test(__NR_signalfd4, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	/* `mask` and `flags` are not catched BPF side. */
	int32_t mock_fd = -1;
	sigset_t mask = {0};
	size_t sizemask = 0;
	int flags = 7;
	assert_syscall_state(SYSCALL_FAILURE, "signalfd4", syscall(__NR_signalfd4, mock_fd, &mask, sizemask, flags));

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
	/* Right now we don't catch any flag, so we expect `0` as a second parameter. */
	evt_test->assert_numeric_param(3, (uint8_t)0);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}
#endif

#include "../../event_class/event_class.h"

#ifdef __NR_signalfd4

#include <sys/signalfd.h>

TEST(SyscallExit, signalfd4X)
{

	/* Please note:
	 * the syscall `signalfd4` is mapped to `PPME_SYSCALL_SIGNALFD_X` event
	 * like `signalfd`. The same BPF program will be used for both the syscalls.
	 */

	auto evt_test = new event_test(__NR_signalfd4, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	/* `mask` and `flags` are not catched BPF side. */
	int32_t mock_fd = -1;
	sigset_t mask = {0};
	int flags = 7;
	assert_syscall_state(SYSCALL_FAILURE, "signalfd4", syscall(__NR_signalfd4, mock_fd, &mask, flags));
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

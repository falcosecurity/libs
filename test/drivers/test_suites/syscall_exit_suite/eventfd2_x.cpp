#include "../../event_class/event_class.h"

#if defined(__NR_eventfd2) && defined(__NR_close)
TEST(SyscallExit, eventfd2X)
{

	/* Please note:
	 * the syscall `eventfd2` is mapped to `PPME_SYSCALL_EVENTFD_X` event
	 * like `eventfd`. The same BPF program will be used for both the syscalls.
	 */

	auto evt_test = get_syscall_event_test(__NR_eventfd2, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	uint32_t initval = 3;
	int flags = 0;
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

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif

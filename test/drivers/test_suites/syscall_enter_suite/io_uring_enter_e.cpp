#include "../../event_class/event_class.h"

#if defined(__NR_io_uring_enter)

#include <linux/io_uring.h>

TEST(SyscallEnter, io_uring_enterE)
{
	auto evt_test = get_syscall_event_test(__NR_io_uring_enter, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t fd = -1;
	uint32_t to_submit = 10;
	uint32_t min_complete = 20;
	uint32_t flags = 0;
	const void* argp = NULL;
	size_t argsz = 7;
	assert_syscall_state(SYSCALL_FAILURE, "io_uring_enter", syscall(__NR_io_uring_enter, fd, to_submit, min_complete, flags, argp, argsz));

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

	// Here we have no parameters to assert.

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(0);
}
#endif

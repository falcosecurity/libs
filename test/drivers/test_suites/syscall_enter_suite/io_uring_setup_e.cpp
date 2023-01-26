#include "../../event_class/event_class.h"

#if defined(__NR_io_uring_setup)

#include <linux/io_uring.h>

TEST(SyscallEnter, io_uring_setupE)
{
	auto evt_test = get_syscall_event_test(__NR_io_uring_setup, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	uint32_t entries = 4;
	struct io_uring_params* params_pointer = NULL;
	assert_syscall_state(SYSCALL_FAILURE, "io_uring_setup", syscall(__NR_io_uring_setup, entries, params_pointer));

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

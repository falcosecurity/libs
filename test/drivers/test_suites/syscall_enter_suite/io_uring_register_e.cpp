#include "../../event_class/event_class.h"

#if defined(__NR_io_uring_register)

#include <linux/io_uring.h>

TEST(SyscallEnter, io_uring_registerE)
{
	auto evt_test = get_syscall_event_test(__NR_io_uring_register, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t fd = -1;
	uint32_t opcode = 0;
	const void* arg = NULL;
	unsigned int nr_args = 7;
	assert_syscall_state(SYSCALL_FAILURE, "io_uring_register", syscall(__NR_io_uring_register, fd, opcode, arg, nr_args));

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

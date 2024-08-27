#include "../../event_class/event_class.h"

#if defined(__NR_io_uring_register)

#include <linux/io_uring.h>

TEST(SyscallExit, io_uring_registerX)
{
	auto evt_test = get_syscall_event_test(__NR_io_uring_register, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t fd = -1;
	uint32_t opcode = 0;
#ifdef IORING_REGISTER_RESTRICTIONS
	opcode = IORING_REGISTER_RESTRICTIONS;
#endif
	const void* arg = (const void*)0x7fff5694dc58;
	unsigned int nr_args = 34;
	assert_syscall_state(SYSCALL_FAILURE, "io_uring_register", syscall(__NR_io_uring_register, fd, opcode, arg, nr_args));
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

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/* Parameter 2: fd (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)fd);

	/* Parameter 3: opcode (type: PT_ENUMFLAGS16) */
	evt_test->assert_numeric_param(3, (uint16_t)opcode);

	/* Parameter 4: arg (type: PT_UINT64) */
	evt_test->assert_numeric_param(4, (uint64_t)arg);

	/* Parameter 5: nr_args (type: PT_UINT32) */
	evt_test->assert_numeric_param(5, (uint32_t)nr_args);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}
#endif

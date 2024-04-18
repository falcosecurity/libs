#include "../../event_class/event_class.h"

#ifdef __NR_copy_file_range
TEST(SyscallExit, copy_file_rangeX)
{
	auto evt_test = get_syscall_event_test(__NR_copy_file_range, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t fd_in = -3;
	int32_t fd_out = -4;
	off64_t off_in = 140;
	off64_t off_out = 300;
	size_t len = 20;
	uint32_t flags = 0;
	assert_syscall_state(SYSCALL_FAILURE, "copy_file_range", syscall(__NR_copy_file_range, fd_in, off_in, fd_out, off_out, len, flags));
	int64_t errno_value = -errno;

	/*=============================== TRIGGER SYSCALL  ===========================*/

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
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/* Parameter 2: fdout (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)fd_out);

	/* Parameter 3: offout (type: PT_UINT64) */
	evt_test->assert_numeric_param(3, (uint64_t)off_out);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}
#endif

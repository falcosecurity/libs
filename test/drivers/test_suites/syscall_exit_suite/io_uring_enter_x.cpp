#include "../../event_class/event_class.h"

#if defined(__NR_io_uring_enter) && defined(__NR_close)

#include <linux/io_uring.h>

TEST(SyscallExit, io_uring_enterX)
{
	auto evt_test = get_syscall_event_test(__NR_io_uring_enter, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t fd = -1;
	uint32_t to_submit = 10;
	uint32_t min_complete = 20;
	uint32_t flags = 0;
	uint32_t expected_flags = 0;
#ifdef IORING_ENTER_EXT_ARG
	flags = IORING_ENTER_EXT_ARG;
	expected_flags = PPM_IORING_ENTER_EXT_ARG;
#endif
	const void* argp = NULL;
	size_t argsz = 7;
	assert_syscall_state(SYSCALL_FAILURE, "io_uring_enter", syscall(__NR_io_uring_enter, fd, to_submit, min_complete, flags, argp, argsz));
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

	/* Parameter 3: to_submit (type: PT_UINT32) */
	evt_test->assert_numeric_param(3, (uint32_t)to_submit);

	/* Parameter 4: min_complete (type: PT_UINT32) */
	evt_test->assert_numeric_param(4, (uint32_t)min_complete);

	/* Parameter 5: flags (type: PT_FLAGS32) */
	evt_test->assert_numeric_param(5, (uint32_t)expected_flags);

	/* Parameter 6: sig (type: PT_SIGSET) */
	/* These are the first 32 bit of a pointer so in this case all zeros */
	evt_test->assert_numeric_param(6, (uint32_t)0);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(6);
}
#endif

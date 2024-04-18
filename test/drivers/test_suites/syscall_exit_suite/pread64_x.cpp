#include "../../event_class/event_class.h"

#include <unistd.h>
#include <sys/uio.h>

#ifdef __NR_pread64

TEST(SyscallExit, preadX_fail)
{
	auto evt_test = get_syscall_event_test(__NR_pread64, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t fd = -1;
	size_t size = 13;
	off_t pos = 17;
	assert_syscall_state(SYSCALL_FAILURE, "preadv", syscall(__NR_pread64, fd, nullptr, size, pos));
	int64_t errno_value = (int64_t)-errno;

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
	evt_test->assert_numeric_param(1, errno_value);

	/* Parameter 2: data (type: PT_BYTEBUF) */
	evt_test->assert_empty_param(2);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

#endif
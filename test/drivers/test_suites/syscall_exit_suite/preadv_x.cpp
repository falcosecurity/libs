#include "../../event_class/event_class.h"

#include <unistd.h>
#include <sys/uio.h>

#ifdef __NR_preadv

TEST(SyscallExit, preadvX_fail)
{
	auto evt_test = get_syscall_event_test(__NR_preadv, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	char buf[16];
	iovec iov[] = {{buf, 16}};
	int32_t fd = -1;
	int32_t iovcnt = 7;
	assert_syscall_state(SYSCALL_FAILURE, "preadv", syscall(__NR_preadv, fd, iov, iovcnt, 0));
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

	/* Parameter 2: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (uint32_t)0);

	/* Parameter 3: data (type: PT_BYTEBUF) */
	evt_test->assert_empty_param(3);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}

#endif
#include "../../event_class/event_class.h"

#ifdef __NR_read

#if defined(__NR_close) && defined(__NR_open)

TEST(SyscallExit, readX_no_snaplen)
{
	auto evt_test = get_syscall_event_test(__NR_read, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Open /dev/urandom for reading */
	int fd = syscall(__NR_open, "/dev/urandom", O_RDONLY);
	assert_syscall_state(SYSCALL_SUCCESS, "open", fd, NOT_EQUAL, -1);

	/* Read data from /dev/urandom */
	const unsigned data_len = DEFAULT_SNAPLEN / 2;
	char buf[data_len];
	ssize_t read_bytes = syscall(__NR_read, fd, (void *)buf, data_len);
	assert_syscall_state(SYSCALL_SUCCESS, "read", read_bytes, NOT_EQUAL, -1);

	/* Close /dev/urandom fd */
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

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)read_bytes);

	/* Parameter 2: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(2, buf, read_bytes);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

TEST(SyscallExit, readX_snaplen)
{
	auto evt_test = get_syscall_event_test(__NR_read, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Open /dev/urandom for reading */
	int fd = syscall(__NR_open, "/dev/urandom", O_RDONLY);
	assert_syscall_state(SYSCALL_SUCCESS, "open", fd, NOT_EQUAL, -1);

	/* Read data from /dev/urandom */
	const unsigned data_len = DEFAULT_SNAPLEN * 2;
	char buf[data_len];
	ssize_t read_bytes = syscall(__NR_read, fd, (void *)buf, data_len);
	assert_syscall_state(SYSCALL_SUCCESS, "read", read_bytes, NOT_EQUAL, -1);

	/* Close /dev/urandom fd */
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

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)read_bytes);

	/* Parameter 2: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(2, buf, DEFAULT_SNAPLEN);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

TEST(SyscallExit, readXfail)
{
	auto evt_test = get_syscall_event_test(__NR_read, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Read data from an invalid fd */
	const unsigned data_len = 64;
	char buf[data_len];
	ssize_t read_bytes = syscall(__NR_read, -1, (void *)buf, data_len);
	int errno_value = -errno;
	assert_syscall_state(SYSCALL_FAILURE, "read", read_bytes);

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

	/* Parameter 2: data (type: PT_BYTEBUF) */
	evt_test->assert_empty_param(2);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

#endif
#endif

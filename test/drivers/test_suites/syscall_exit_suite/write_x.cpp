#include "../../event_class/event_class.h"
#include "../../helpers/file_opener.h"

#ifdef __NR_write

#if defined(__NR_close) && defined(__NR_openat) && defined(__NR_close)

TEST(SyscallExit, writeX_no_snaplen)
{
	auto evt_test = get_syscall_event_test(__NR_write, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Open a generic file for writing */
	auto fo = file_opener(".", (O_WRONLY | O_TMPFILE));
	int fd = fo.get_fd();

	/* Write data to the generic file */
	const unsigned data_len = DEFAULT_SNAPLEN / 2;
	char buf[data_len] = "hello\0";
	ssize_t write_bytes = syscall(__NR_write, fd, (void *)buf, data_len);
	assert_syscall_state(SYSCALL_SUCCESS, "write", write_bytes, NOT_EQUAL, -1);

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
	evt_test->assert_numeric_param(1, (int64_t)write_bytes);

	/* Parameter 2: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(2, buf, write_bytes);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

TEST(SyscallExit, writeX_snaplen)
{
	auto evt_test = get_syscall_event_test(__NR_write, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Open a generic file for writing */
	auto fo = file_opener(".", (O_WRONLY | O_TMPFILE));
	int fd = fo.get_fd();

	/* Write data to the generic file */
	const unsigned data_len = DEFAULT_SNAPLEN * 2;
	char buf[data_len] = "hello\0";
	ssize_t write_bytes = syscall(__NR_write, fd, (void *)buf, data_len);
	assert_syscall_state(SYSCALL_SUCCESS, "write", write_bytes, NOT_EQUAL, -1);

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
	evt_test->assert_numeric_param(1, (int64_t)write_bytes);

	/* Parameter 2: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(2, buf, DEFAULT_SNAPLEN);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

TEST(SyscallExit, writeX_fail)
{
	auto evt_test = get_syscall_event_test(__NR_write, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Write data to an invalid fd */
	const unsigned data_len = DEFAULT_SNAPLEN * 2;
	char buf[data_len] = "some-data";
	assert_syscall_state(SYSCALL_FAILURE, "write", syscall(__NR_write, -1, (void *)buf, data_len));
	int errno_value = -errno;

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
	evt_test->assert_bytebuf_param(2, buf, DEFAULT_SNAPLEN);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

TEST(SyscallExit, writeX_empty)
{
	auto evt_test = get_syscall_event_test(__NR_write, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	const unsigned data_len = 6;
	char *buf = NULL;
	assert_syscall_state(SYSCALL_FAILURE, "write", syscall(__NR_write, -1, (void *)buf, data_len));
	int errno_value = -errno;

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

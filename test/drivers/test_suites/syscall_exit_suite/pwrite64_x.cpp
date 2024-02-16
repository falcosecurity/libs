#include "../../event_class/event_class.h"

#ifdef __NR_pwrite64

#if defined(__NR_close) && defined(__NR_open) && defined(__NR_close)

TEST(SyscallExit, pwrite64X_no_snaplen)
{
	auto evt_test = get_syscall_event_test(__NR_pwrite64, EXIT_EVENT);

	syscall(__NR_openat, AT_FDCWD, ".", O_RDWR | O_TMPFILE, 0);
	bool notmpfile = (errno == EOPNOTSUPP);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Open a generic file for writing */
	const char* pathname = notmpfile? ".tmpfile" : ".";
	int flags = notmpfile? (O_WRONLY | O_CREAT) : (O_WRONLY | O_TMPFILE);
	int fd = syscall(__NR_open, pathname, flags);
	assert_syscall_state(SYSCALL_SUCCESS, "open", fd, NOT_EQUAL, -1);

	/* Write data to the generic file */
	const unsigned data_len = DEFAULT_SNAPLEN / 2;
	char buf[data_len] = "hello\0";
	off_t off = 0;
	assert_syscall_state(SYSCALL_SUCCESS, "pwrite64", syscall(__NR_pwrite64, fd, (void *)buf, data_len, off), NOT_EQUAL, -1);

	/* Close the generic file */
	syscall(__NR_close, fd);

	if(notmpfile)
	{
		unlink(pathname);
	}

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
	evt_test->assert_numeric_param(1, (int64_t)DEFAULT_SNAPLEN / 2);

	/* Parameter 2: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(2, buf, DEFAULT_SNAPLEN / 2);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

TEST(SyscallExit, pwrite64X_snaplen)
{
	auto evt_test = get_syscall_event_test(__NR_pwrite64, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	const unsigned data_len = DEFAULT_SNAPLEN * 2;
	char buf[data_len] = "some-data";
	off_t off = 0;
	assert_syscall_state(SYSCALL_FAILURE, "pwrite64", syscall(__NR_pwrite64, -1, (void *)buf, data_len, off));
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

TEST(SyscallExit, pwrite64X_fail)
{
	auto evt_test = get_syscall_event_test(__NR_pwrite64, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Write data to an invalid fd */
	const unsigned data_len = 64;
	char *buf = NULL;
	off_t off = 0;
	assert_syscall_state(SYSCALL_FAILURE, "pwrite64", syscall(__NR_pwrite64, -1, (void *)buf, data_len, off));
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

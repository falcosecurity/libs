#include "../../event_class/event_class.h"
#include "../../helpers/file_opener.h"

#ifdef __NR_pwritev

#if defined(__NR_close) && defined(__NR_openat) && defined(__NR_close)

TEST(SyscallExit, pwritevX_no_snaplen)
{
	auto evt_test = get_syscall_event_test(__NR_pwritev, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int mock_fd = -12;
	struct iovec iov[1];
	memset(iov, 0, sizeof(iov));
	char sent_data_1[DEFAULT_SNAPLEN / 2] = "some-data";
	iov[0].iov_base = sent_data_1;
	iov[0].iov_len = sizeof(sent_data_1);
	int32_t iovcnt = 1;
	off_t off = 1;
	assert_syscall_state(SYSCALL_FAILURE, "pwritev", syscall(__NR_pwritev, mock_fd, iov, iovcnt, off));
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

	/* Parameter 2: data (type: PT_BYTEBUF) */
	/* This proves that even if the syscall fails we can collect less than DEFAULT_SNAPLEN */
	evt_test->assert_bytebuf_param(2, sent_data_1, DEFAULT_SNAPLEN / 2);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

TEST(SyscallExit, pwritevX_snaplen)
{
	auto evt_test = get_syscall_event_test(__NR_pwritev, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Open a generic file for writing */
	auto fo = file_opener(".", (O_WRONLY | O_TMPFILE));
	int fd = fo.get_fd();
	assert_syscall_state(SYSCALL_SUCCESS, "open", fd, NOT_EQUAL, -1);

	struct iovec iov[2];
	memset(iov, 0, sizeof(iov));
	char sent_data_1[DEFAULT_SNAPLEN] = "some-data";
	char sent_data_2[DEFAULT_SNAPLEN] = "some-other-data";
	iov[0].iov_base = sent_data_1;
	iov[1].iov_base = sent_data_2;
	iov[0].iov_len = sizeof(sent_data_1);
	iov[1].iov_len = sizeof(sent_data_2);
	int32_t iovcnt = 2;
	off_t off = 0;
	assert_syscall_state(SYSCALL_SUCCESS, "pwritev", syscall(__NR_pwritev, fd, iov, iovcnt, off), NOT_EQUAL, -1);

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
	evt_test->assert_numeric_param(1, (int64_t)DEFAULT_SNAPLEN * 2);

	/* Parameter 2: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(2, sent_data_1, DEFAULT_SNAPLEN);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

TEST(SyscallExit, pwritevX_empty)
{
	auto evt_test = get_syscall_event_test(__NR_pwritev, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int mock_fd = -12;
	iovec* iov = NULL;
	int32_t iovcnt = 7;
	off_t off = 0;
	assert_syscall_state(SYSCALL_FAILURE, "pwritev", syscall(__NR_pwritev, mock_fd, iov, iovcnt, off));
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

	/* Parameter 2: data (type: PT_BYTEBUF) */
	evt_test->assert_empty_param(2);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

#endif
#endif

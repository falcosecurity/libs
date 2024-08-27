#include "../../event_class/event_class.h"

#ifdef __NR_readv

TEST(SyscallExit, readvX_fail)
{
	auto evt_test = get_syscall_event_test(__NR_readv, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	char buf[16];
	iovec iov[] = {{buf, 16}};
	int32_t fd = -1;
	int32_t iovcnt = 7;
	assert_syscall_state(SYSCALL_FAILURE, "readv", syscall(__NR_readv, fd, iov, iovcnt));
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

TEST(SyscallExit, readvX_success)
{
	auto evt_test = get_syscall_event_test(__NR_readv, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	/* Create a non blocking pipe, so that we can read and write from and to it without touching the filesystem */
	int pipefds[2];
	ASSERT_EQ(pipe2(pipefds, O_NONBLOCK), 0);

	/* Write a string into it */
	const char *test_string = "this is a string used for testing purposes";
	ASSERT_EQ(write(pipefds[1], (void *)test_string, strlen(test_string) + 1), strlen(test_string) + 1);

	/* Try to read the string with readv using three buffers */
	int32_t iovcnt = 3;
	iovec iov[iovcnt];
	size_t buf_size = 15;
	ASSERT_GT(iovcnt * buf_size, strlen(test_string) + 1);

	for(int i = 0; i < iovcnt; i++)
	{
		iov[i].iov_base = (void *)new char[buf_size];
		iov[i].iov_len = buf_size;
	}

	assert_syscall_state(SYSCALL_SUCCESS, "readv", syscall(__NR_readv, pipefds[0], iov, iovcnt), EQUAL, strlen(test_string) + 1);

	for(int i = 0; i < iovcnt; i++)
	{
		delete(char *)iov[i].iov_base;
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
	evt_test->assert_numeric_param(1, (int64_t)strlen(test_string) + 1);

	/* Parameter 2: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (uint32_t)strlen(test_string) + 1);

	/* Parameter 3: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(3, test_string, strlen(test_string) + 1);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}

#endif

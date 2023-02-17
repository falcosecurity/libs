#include "../../event_class/event_class.h"

#ifdef __NR_write

#if defined(__NR_close) && defined(__NR_open) && defined(__NR_unlink)

TEST(SyscallExit, writeX_no_snaplen)
{
	auto evt_test = get_syscall_event_test(__NR_write, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Open ./testfile for writing */
	int fd = syscall(__NR_open, "./testfile", O_WRONLY|O_CREAT);
	assert_syscall_state(SYSCALL_SUCCESS, "write", fd, NOT_EQUAL, -1);

	/* Write data to ./testfile */
	const unsigned data_len = 5;
	char buf[data_len] = "hi\0";
	ssize_t write_bytes = syscall(__NR_write, fd, (void *)buf, data_len);
	assert_syscall_state(SYSCALL_SUCCESS, "write", write_bytes, NOT_EQUAL, -1);

	/* Close ./testfile */
	syscall(__NR_close, fd);

	/* Unlink ./testfile */
	syscall(__NR_unlink, "./testfile");

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

	/* Open ./testfile for writing */
	int fd = syscall(__NR_open, "./testfile", O_CREAT);
	assert_syscall_state(SYSCALL_SUCCESS, "open", fd, NOT_EQUAL, -1);

	/* Write data to ./testfile */
	const unsigned data_len = 846; /* Something greater than DEFAULT_SNAPLEN */
	char buf[data_len] = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nam lacinia turpis velit, sit amet porta purus dictum et. Integer vitae aliquam justo, eu euismod felis. Nam metus odio, pharetra eget urna accumsan, rhoncus pulvinar orci. Suspendisse sit amet urna lacus. Sed non metus tristique, gravida justo eu, porttitor ex. Interdum et malesuada fames ac ante ipsum primis in faucibus. Morbi suscipit placerat porttitor. Duis non nunc ut enim pulvinar interdum. Donec sit amet ipsum nisi. Phasellus vel justo urna. Donec sed orci vitae mi consectetur feugiat. Fusce sodales pharetra interdum. Maecenas feugiat sodales orci, ut egestas dui lacinia vitae. Nulla aliquam nulla nulla, ut eleifend turpis porta id. Vestibulum interdum lacus in turpis posuere, non scelerisque nulla rhoncus. Pellentesque non enim vitae eros vestibulum rutrum in et lacus.";
	ssize_t write_bytes = syscall(__NR_write, fd, (void *)buf, data_len);
	assert_syscall_state(SYSCALL_SUCCESS, "write", write_bytes, NOT_EQUAL, -1);

	/* Close ./testfile */
	syscall(__NR_close, fd);

	/* Unlink ./testfile */
	syscall(__NR_unlink, "./testfile");

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

TEST(SyscallExit, writeXfail)
{
	auto evt_test = get_syscall_event_test(__NR_write, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Write data to an invalid fd */
	const unsigned data_len = 64;
	char buf[data_len];
	ssize_t write_bytes = syscall(__NR_write, -1, (void *)buf, data_len);
	int errno_value = -errno;
	assert_syscall_state(SYSCALL_FAILURE, "write", write_bytes);

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

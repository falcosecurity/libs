#include "../../event_class/event_class.h"

#if defined(__NR_dup) && defined(__NR_openat) && defined(__NR_close)
TEST(SyscallExit, dupX)
{
	auto evt_test = get_syscall_event_test(__NR_dup, EXIT_EVENT);

	syscall(__NR_openat, AT_FDCWD, ".", O_RDWR | O_TMPFILE, 0);
	bool notmpfile = (errno == EOPNOTSUPP);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	const char* pathname = notmpfile? ".tmpfile" : ".";
	int oflags = notmpfile? (O_RDWR | O_CREAT) : (O_RDWR | O_TMPFILE);
	int32_t old_fd = syscall(__NR_openat, AT_FDCWD, pathname, oflags);
	assert_syscall_state(SYSCALL_SUCCESS, "openat", old_fd, NOT_EQUAL, -1);

	int32_t new_fd = syscall(__NR_dup, old_fd);
	assert_syscall_state(SYSCALL_SUCCESS, "dup", new_fd, NOT_EQUAL, -1);

	syscall(__NR_close, old_fd);
	syscall(__NR_close, new_fd);

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

	if(notmpfile)
	{
		unlink(pathname);
	}

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_FD) */
	evt_test->assert_numeric_param(1, (int64_t)new_fd);

	/* Parameter 2: oldfd (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)old_fd);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}
#endif

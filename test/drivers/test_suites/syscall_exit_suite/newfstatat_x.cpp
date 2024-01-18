#include "../../event_class/event_class.h"

#ifdef __NR_newfstatat
TEST(SyscallExit, newfstatatX_success)
{
	auto evt_test = get_syscall_event_test(__NR_newfstatat, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

    int dirfd = AT_FDCWD;
	const char* pathname = ".";
    struct stat buffer;
	int flags = AT_NO_AUTOMOUNT | AT_SYMLINK_NOFOLLOW;

	int32_t res = syscall(__NR_newfstatat, dirfd, pathname, &buffer, flags);
	assert_syscall_state(SYSCALL_SUCCESS, "newfstatat", res, NOT_EQUAL, -1);

	/*=============================== TRIGGER SYSCALL  ===========================*/

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
	evt_test->assert_numeric_param(1, (int64_t)res);

	/* Parameter 2: dirfd (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)PPM_AT_FDCWD);

	/* Parameter 3: name (type: PT_FSPATH) */
	evt_test->assert_charbuf_param(3, pathname);

	/* Parameter 4: stat (type: PT_BYTEBUF) */
	//evt_test->assert_numeric_param(4, );

	/* Parameter 4: flags (type: PT_FLAGS32) */
	evt_test->assert_numeric_param(4, (uint32_t)PPM_AT_NO_AUTOMOUNT | PPM_AT_SYMLINK_NOFOLLOW);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);
}

TEST(SyscallExit, newfstatatX_failure)
{
	auto evt_test = get_syscall_event_test(__NR_newfstatat, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

    int dirfd = AT_FDCWD;
	const char* pathname = "mock_path";
    struct stat buffer;
	int flags = AT_NO_AUTOMOUNT | AT_SYMLINK_NOFOLLOW;

	int32_t res = syscall(__NR_newfstatat, dirfd, pathname, &buffer, flags);
	assert_syscall_state(SYSCALL_FAILURE, "newfstatat", res);
    int64_t errno_value = -errno;

	/*=============================== TRIGGER SYSCALL  ===========================*/

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

	/* Parameter 2: dirfd (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)PPM_AT_FDCWD);

	/* Parameter 3: name (type: PT_FSPATH) */
	evt_test->assert_charbuf_param(3, pathname);

	/* Parameter 4: stat (type: PT_BYTEBUF) */
	//evt_test->assert_numeric_param(4, );

	/* Parameter 4: flags (type: PT_FLAGS32) */
	evt_test->assert_numeric_param(4, (uint32_t)PPM_AT_NO_AUTOMOUNT | PPM_AT_SYMLINK_NOFOLLOW);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);
}

#endif
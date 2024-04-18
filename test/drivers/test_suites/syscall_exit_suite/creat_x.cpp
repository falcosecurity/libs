#include "../../event_class/event_class.h"

#ifdef __NR_creat

#if defined(__NR_fstat) && defined(__NR_unlinkat) && defined(__NR_close)
TEST(SyscallExit, creatX_success)
{
	auto evt_test = get_syscall_event_test(__NR_creat, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	const char* path = "tmp_file";
	mode_t mode = S_IRWXU;
	int fd = syscall(__NR_creat, path, mode);
	assert_syscall_state(SYSCALL_SUCCESS, "creat", fd, NOT_EQUAL, -1);

	/* Call `fstat` to retrieve the `dev` and `ino`. */
	struct stat file_stat;
	assert_syscall_state(SYSCALL_SUCCESS, "fstat", syscall(__NR_fstat, fd, &file_stat), NOT_EQUAL, -1);
	uint32_t dev = (uint32_t)file_stat.st_dev;
	uint64_t inode = file_stat.st_ino;

	/* Remove the file. */
	syscall(__NR_close, fd);
	syscall(__NR_unlinkat, AT_FDCWD, path, 0);

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

	/* Parameter 1: fd (type: PT_FD) */
	evt_test->assert_numeric_param(1, (int64_t)fd);

	/* Parameter 2: name (type: PT_FSPATH) */
	evt_test->assert_charbuf_param(2, path);

	/* Parameter 3: mode (type: PT_UINT32) */
	evt_test->assert_numeric_param(3, (uint32_t)(PPM_S_IRUSR | PPM_S_IWUSR | PPM_S_IXUSR));

	/* Parameter 4: dev (type: PT_UINT32) */
	evt_test->assert_numeric_param(4, (uint32_t)dev);

	/* Parameter 5: ino (type: PT_UINT64) */
	evt_test->assert_numeric_param(5, (uint64_t)inode);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}
#endif /* defined(__NR_fstat) && defined(__NR_unlinkat) && defined(__NR_close) */

TEST(SyscallExit, creatX_failure)
{
	auto evt_test = get_syscall_event_test(__NR_creat, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	const char* path = "*//null";
	mode_t mode = S_IRGRP;
	assert_syscall_state(SYSCALL_FAILURE, "creat", syscall(__NR_creat, path, mode));
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

	/* Parameter 1: fd (type: PT_FD) */
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/* Parameter 2: name (type: PT_FSPATH) */
	evt_test->assert_charbuf_param(2, path);

	/* Parameter 3: mode (type: PT_UINT32) */
	evt_test->assert_numeric_param(3, (uint32_t)PPM_S_IRGRP);

	/* Parameter 4: dev (type: PT_UINT32) */
	evt_test->assert_numeric_param(4, (uint32_t)0);

	/* Parameter 5: ino (type: PT_UINT64) */
	evt_test->assert_numeric_param(5, (uint64_t)0);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}
#endif

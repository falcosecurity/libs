#include "../../event_class/event_class.h"
#include "../../helpers/file_opener.h"
#include <fcntl.h>

#if defined(__NR_openat) && defined(__NR_fstat)

#include <sys/stat.h> /* Definitions for `fstat` syscall. */

TEST(SyscallExit, openatX_success)
{
	auto evt_test = get_syscall_event_test(__NR_openat, EXIT_EVENT);

	auto fo = file_opener(".", (O_RDWR | O_TMPFILE | O_DIRECTORY));
	bool notmpfile = fo.is_tmpfile_supported();
	fo.close();

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Syscall special notes:
	 * With `O_TMPFILE` flag the pathname must be a directory.
	 */
	int dirfd = AT_FDCWD;
	const char* pathname = notmpfile? ".tmpfile" : ".";
	int flags = notmpfile? (O_RDWR | O_CREAT | O_DIRECTORY) : (O_RDWR | O_TMPFILE | O_DIRECTORY);
	mode_t mode = 0;
	int fd = syscall(__NR_openat, dirfd, pathname, flags, mode);
	assert_syscall_state(SYSCALL_SUCCESS, "openat", fd, NOT_EQUAL, -1);

	/* Call `fstat` to retrieve the `dev` and `ino`. */
	struct stat file_stat;
	assert_syscall_state(SYSCALL_SUCCESS, "fstat", syscall(__NR_fstat, fd, &file_stat), NOT_EQUAL, -1);
	uint32_t dev = (uint32_t)file_stat.st_dev;
	uint64_t inode = file_stat.st_ino;
	close(fd);

	if(notmpfile)
	{
		unlink(pathname);
	}

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

	/* Parameter 2: dirfd (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)PPM_AT_FDCWD);

	/* Parameter 3: name (type: PT_FSPATH) */
	evt_test->assert_charbuf_param(3, pathname);

	/* Parameter 4: flags (type: PT_FLAGS32) */
	flags = notmpfile? (PPM_O_RDWR | PPM_O_CREAT | PPM_O_DIRECTORY) : (PPM_O_RDWR | PPM_O_TMPFILE | PPM_O_DIRECTORY);
	evt_test->assert_numeric_param(4, (uint32_t)flags);

	/* Parameter 5: mode (type: PT_UINT32) */
	evt_test->assert_numeric_param(5, (uint32_t)mode);

	/* Parameter 6: dev (type: PT_UINT32) */
	evt_test->assert_numeric_param(6, (uint32_t)dev);

	/* Parameter 7: ino (type: PT_UINT64) */
	evt_test->assert_numeric_param(7, inode);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(7);
}

TEST(SyscallExit, openatX_failure)
{
	auto evt_test = get_syscall_event_test(__NR_openat, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Syscall special notes:
	 * With `O_TMPFILE` flag the pathname must be a directory
	 * but here it is a filename so the call will fail!
	 */

	int dirfd = AT_FDCWD;
	const char* pathname = "mock_path";
	int flags = O_RDWR | O_TMPFILE | O_DIRECTORY;
	mode_t mode = 0;
	assert_syscall_state(SYSCALL_FAILURE, "openat", syscall(__NR_openat, dirfd, pathname, flags, mode));
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

	/* Parameter 2: dirfd (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)PPM_AT_FDCWD);

	/* Parameter 3: name (type: PT_FSPATH) */
	evt_test->assert_charbuf_param(3, pathname);

	/* Parameter 4: flags (type: PT_FLAGS32) */
	evt_test->assert_numeric_param(4, (uint32_t)PPM_O_RDWR | PPM_O_TMPFILE | PPM_O_DIRECTORY);

	/* Parameter 5: mode (type: PT_UINT32) */
	evt_test->assert_numeric_param(5, (uint32_t)mode);

	/* Syscall fails so dev=0 && ino=0. */

	/* Parameter 6: dev (type: PT_UINT32) */
	evt_test->assert_numeric_param(6, (uint32_t)0);

	/* Parameter 7: ino (type: PT_UINT64) */
	evt_test->assert_numeric_param(7, (uint64_t)0);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(7);
}

TEST(SyscallExit, openatX_create_success)
{
	auto evt_test = get_syscall_event_test(__NR_openat, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int dirfd = AT_FDCWD;
	const char* pathname = "created_file";
	int flags = O_RDWR | O_CREAT;
	mode_t mode = S_IRWXU | S_IRGRP | S_IXGRP;
	syscall(__NR_unlinkat, AT_FDCWD, pathname, 0); /* remove file before creating it */
	int fd = syscall(__NR_openat, dirfd, pathname, flags, mode);
	assert_syscall_state(SYSCALL_SUCCESS, "openat", fd, NOT_EQUAL, -1);

	/* Call `fstat` to retrieve the `dev` and `ino`. */
	struct stat file_stat;
	assert_syscall_state(SYSCALL_SUCCESS, "fstat", syscall(__NR_fstat, fd, &file_stat), NOT_EQUAL, -1);
	uint32_t dev = (uint32_t)file_stat.st_dev;
	uint64_t inode = file_stat.st_ino;
	close(fd);

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

	/* Parameter 2: dirfd (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)PPM_AT_FDCWD);

	/* Parameter 3: name (type: PT_FSPATH) */
	evt_test->assert_charbuf_param(3, pathname);

	/* Parameter 4: flags (type: PT_FLAGS32) */
	evt_test->assert_numeric_param(4, (uint32_t)PPM_O_RDWR | PPM_O_CREAT | PPM_O_F_CREATED);

	/* Parameter 5: mode (type: PT_UINT32) */
	evt_test->assert_numeric_param(5, (uint32_t)mode);

	/* Parameter 6: dev (type: PT_UINT32) */
	evt_test->assert_numeric_param(6, (uint32_t)dev);

	/* Parameter 7: ino (type: PT_UINT64) */
	evt_test->assert_numeric_param(7, inode);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(7);
}
#endif

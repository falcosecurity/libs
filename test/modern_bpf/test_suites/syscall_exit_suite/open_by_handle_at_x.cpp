#include "../../event_class/event_class.h"

#if defined(__NR_open_by_handle_at) && defined(__NR_name_to_handle_at) && defined(__NR_openat)

TEST(SyscallExit, open_by_handle_atX_success)
{
	auto evt_test = new event_test(__NR_open_by_handle_at, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/*
	 * 1. Open a temp file.
	 */
	int dirfd = AT_FDCWD;
	const char *pathname = ".";
	int flags = O_RDWR | O_TMPFILE | O_DIRECTORY;
	mode_t mode = 0;
	int fd = syscall(__NR_openat, dirfd, pathname, flags, mode);
	assert_syscall_state(SYSCALL_SUCCESS, "openat", fd, NOT_EQUAL, -1);

	/* Allocate file_handle structure. */
	struct file_handle *fhp;
	int fhsize = sizeof(*fhp);
	fhp = (struct file_handle *)malloc(fhsize);
	if(fhp == NULL)
	{
		FAIL() << "Error in allocating the `struct file_handle` with malloc" << std::endl;
	}

	/* Make an initial call to name_to_handle_at() to discover the size required for the file handle.
	 * The caller can discover the required size for the file_handle structure by making a call in which handle->handle_bytes is zero;
	 * in this case, the call fails with the error EOVERFLOW and handle->handle_bytes is set to indicate the required size;
	 */
	int mount_id;
	flags = 0;
	fhp->handle_bytes = 0;
	assert_syscall_state(SYSCALL_FAILURE, "name_to_handle_at", syscall(__NR_name_to_handle_at, dirfd, pathname, fhp, &mount_id, flags));

	/*
	 * 2. Reallocate file_handle structure with the correct size.
	 */
	fhsize = sizeof(*fhp) + fhp->handle_bytes;
	fhp = (struct file_handle *)realloc(fhp, fhsize);
	if(fhp == NULL)
	{
		FAIL() << "Error in allocating the `struct file_handle` with realloc" << std::endl;
	}

	/*
	 * 3. Get file handle.
	 */
	assert_syscall_state(SYSCALL_SUCCESS, "name_to_handle_at", syscall(__NR_name_to_handle_at, dirfd, pathname, fhp, &mount_id, flags), NOT_EQUAL, -1);

	/*
	 * 4. Call `open_by_handle_at`.
	 */
	flags = O_RDONLY;
	int open_by_handle_fd = syscall(__NR_open_by_handle_at, AT_FDCWD, fhp, flags);
	assert_syscall_state(SYSCALL_SUCCESS, "open_by_handle_at", open_by_handle_fd, NOT_EQUAL, -1);

	/*
	 * 5. Get the current working directory.
	 */
	char tmp[4096];
	char *err = getcwd(tmp, 4096);
	if(!err)
	{
		FAIL() << "Could not get the current working directory" << std::endl;
	}

	/*
	 * 6. Cleaning phase.
	 */
	close(open_by_handle_fd);
	close(fd);
	free(fhp);

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

	/* Parameter 1: ret (type: PT_FD) */
	evt_test->assert_numeric_param(1, (int64_t)open_by_handle_fd);

	/* Parameter 2: mountfd (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)PPM_AT_FDCWD);

	/* Parameter 3: flags (type: PT_FLAGS32) */
	evt_test->assert_numeric_param(3, (uint32_t)PPM_O_RDONLY);

	/* Parameter 4: path (type: PT_FSPATH) */
	evt_test->assert_charbuf_param(4, tmp);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);
}

TEST(SyscallExit, open_by_handle_atX_failure)
{
	auto evt_test = new event_test(__NR_open_by_handle_at, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Syscall special notes:
	 * Here `mount_fd` is invalid so the call will fail.
	 */

	int mount_fd = -1;
	struct file_handle *fhp = NULL;
	int flags = O_RDWR;
	assert_syscall_state(SYSCALL_FAILURE, "open_by_handle_at", syscall(__NR_open_by_handle_at, mount_fd, fhp, flags));
	int64_t errno_value = -errno;

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure())
	{
		/* This could happen if:
		 * - the syscall result state is different from the expected one.
		 * - we are not able to find the event in the ring buffers.
		 */
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: ret (type: PT_FD) */
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/* Parameter 2: mountfd (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)mount_fd);

	/* Parameter 3: flags (type: PT_FLAGS32) */
	evt_test->assert_numeric_param(3, (uint32_t)PPM_O_RDWR);

	/* Parameter 4: path (type: PT_FSPATH) */
	evt_test->assert_empty_param(4);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);
}
#endif

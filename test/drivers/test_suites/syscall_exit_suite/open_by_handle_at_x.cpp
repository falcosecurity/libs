#include <fcntl.h>
#include <libscap/strl.h>
#include "../../event_class/event_class.h"
#include "../../helpers/file_opener.h"
#include <sys/mount.h>

#if defined(__NR_open_by_handle_at) && defined(__NR_name_to_handle_at) && defined(__NR_openat)

#define MAX_FSPATH_LEN	4096

void do___open_by_handle_atX_success(int *open_by_handle_fd, int *dirfd, char *fspath, uint32_t *dev, uint64_t *inode, int use_mountpoint)
{
	/*
	 * 0. Create (temporary) mount point (if use_mountpoint).
	 */
	char tmpdir[] = "/tmp/modern.bpf.open_by_handle_atX_success_mp.XXXXXX";
	char *dir_name = NULL;
	*dirfd = AT_FDCWD;
	if(use_mountpoint)
	{
		int rc;

		dir_name = mkdtemp(tmpdir);
		if (dir_name == NULL)
		{
			FAIL() << "Could not create temporary directory" << std::endl;
		}

		rc = syscall(__NR_mount, "none", dir_name, "tmpfs", 0, "size=1M,uid=0,gid=0,mode=700");
		assert_syscall_state(SYSCALL_SUCCESS, "mount", rc, NOT_EQUAL, -1);

		/* Since `dir_name` is always an absolute path `dirfd` can be `0` here. */
		*dirfd = syscall(__NR_openat, 0, dir_name, O_DIRECTORY);
		assert_syscall_state(SYSCALL_SUCCESS, "openat", *dirfd, NOT_EQUAL, -1);
	}

	/*
	 * 1. Open a temp file.
	 */

	auto fo = file_opener(".", (O_RDWR | O_TMPFILE), *dirfd);

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
	int flags = 0;
	fhp->handle_bytes = 0;
	assert_syscall_state(SYSCALL_FAILURE, "name_to_handle_at", syscall(__NR_name_to_handle_at, *dirfd, fo.get_pathname(), fhp, &mount_id, flags));

	/*
	 * 2. Reallocate file_handle structure with the correct size.
	 */
	fhsize = sizeof(*fhp) + fhp->handle_bytes;
	struct file_handle *new_fhp = (struct file_handle *)realloc(fhp, fhsize);
	if(new_fhp == NULL)
	{
		free(fhp);
		FAIL() << "Error in allocating the `struct file_handle` with realloc" << std::endl;
	}
	fhp = new_fhp;

	/*
	 * 3. Get file handle.
	 */
	assert_syscall_state(SYSCALL_SUCCESS, "name_to_handle_at", syscall(__NR_name_to_handle_at, *dirfd, fo.get_pathname(), fhp, &mount_id, flags), NOT_EQUAL, -1);

	/*
	 * 4. Call `open_by_handle_at`.
	 */
	flags = O_RDONLY;
	mount_id = use_mountpoint ? *dirfd : AT_FDCWD;
	*open_by_handle_fd = syscall(__NR_open_by_handle_at, mount_id, fhp, flags);
	assert_syscall_state(SYSCALL_SUCCESS, "open_by_handle_at", *open_by_handle_fd, NOT_EQUAL, -1);

	/*
	 * 5. Get the current working directory.
	 */
	if(use_mountpoint)
	{
		strlcpy(fspath, dir_name, MAX_FSPATH_LEN);
	}
	else
	{
		char *err = getcwd(fspath, MAX_FSPATH_LEN);
		if(!err)
		{
			FAIL() << "Could not get the current working directory" << std::endl;
		}
	}

	/*
	 * 6. Get dev and ino.
	 */
	struct stat file_stat;
	assert_syscall_state(SYSCALL_SUCCESS, "fstat", syscall(__NR_fstat, *open_by_handle_fd, &file_stat), NOT_EQUAL, -1);
	*dev = (uint32_t)file_stat.st_dev;
	*inode = file_stat.st_ino;

	/*
	 * 7. Cleaning phase.
	 */
	close(*open_by_handle_fd);
	free(fhp);

	if(use_mountpoint)
	{
		close(*dirfd);
		umount(dir_name);
		rmdir(dir_name);
	}

}

TEST(SyscallExit, open_by_handle_atX_success)
{
	auto evt_test = get_syscall_event_test(__NR_open_by_handle_at, EXIT_EVENT);

	auto fo = file_opener(".", (O_RDWR | O_TMPFILE | O_DIRECTORY));

	if(!fo.get_fd())
	{
		FAIL() << "Error opening current directory" << std::endl;
	}
	struct file_handle *fhp;
	fhp = (struct file_handle *)malloc(sizeof(*fhp) + sizeof(fhp->handle_bytes));
	if(fhp == NULL)
	{
		FAIL() << "Error in allocating the `struct file_handle` with malloc" << std::endl;
	}
	int mount_id;
	fhp->handle_bytes = 0;
	if(syscall(__NR_name_to_handle_at, AT_FDCWD, fo.get_pathname(), fhp, &mount_id, 0) != 0 && errno == EOPNOTSUPP)
	{
		/*
		 * Run the test only if the filesystem supports name_to_handle_at.
		 */
		GTEST_SKIP() << "[NAME_TO_HANDLE_AT]: the current filesystem doesn't support this operation." << std::endl;
	}

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int open_by_handle_fd;
	int dirfd;
	char fspath[MAX_FSPATH_LEN];
	uint32_t dev;
	uint64_t inode;
	do___open_by_handle_atX_success(&open_by_handle_fd, &dirfd, fspath, &dev, &inode, 0);
	
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
	evt_test->assert_numeric_param(2, (int64_t)dirfd);

	/* Parameter 3: flags (type: PT_FLAGS32) */
	evt_test->assert_numeric_param(3, (uint32_t)PPM_O_RDONLY);

	/* Parameter 4: path (type: PT_FSPATH) */
	evt_test->assert_charbuf_param(4, fspath);

	/* Parameter 5: dev (type: PT_UINT32) */
	evt_test->assert_numeric_param(5, dev);

	/* Parameter 6: ino (type: PT_UINT64) */
	evt_test->assert_numeric_param(6, inode);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(6);

}

TEST(SyscallExit, open_by_handle_atX_success_mp)
{
	auto evt_test = get_syscall_event_test(__NR_open_by_handle_at, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int open_by_handle_fd;
	int dirfd;
	char fspath[MAX_FSPATH_LEN];
	uint32_t dev;
	uint64_t inode;
	do___open_by_handle_atX_success(&open_by_handle_fd, &dirfd, fspath, &dev, &inode, 1);

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
	evt_test->assert_numeric_param(2, (int64_t)dirfd);

	/* Parameter 3: flags (type: PT_FLAGS32) */
	evt_test->assert_numeric_param(3, (uint32_t)PPM_O_RDONLY);

	/* Parameter 4: path (type: PT_FSPATH) */
	evt_test->assert_charbuf_param(4, fspath);

	/* Parameter 5: dev (type: PT_UINT32) */
	evt_test->assert_numeric_param(5, dev);

	/* Parameter 6: ino (type: PT_UINT64) */
	evt_test->assert_numeric_param(6, inode);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(6);
}

TEST(SyscallExit, open_by_handle_atX_failure)
{
	auto evt_test = get_syscall_event_test(__NR_open_by_handle_at, EXIT_EVENT);

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

	/* Parameter 5: dev (type: PT_UINT32) */
	evt_test->assert_numeric_param(5, (uint32_t)0);

	/* Parameter 6: ino (type: PT_UINT64) */
	evt_test->assert_numeric_param(6, (uint64_t)0);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(6);
}
#endif

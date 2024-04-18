#include "../../event_class/event_class.h"
#if defined(__NR_mknod)
#include <sys/sysmacros.h>
TEST(SyscallExit, mknodX_failure)
{
	auto evt_test = get_syscall_event_test(__NR_mknod, EXIT_EVENT);
	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	char path[] = "/tmp/";

	uint32_t mode = 0060000 | 0666;
	uint32_t dev = 61440;
	assert_syscall_state(SYSCALL_FAILURE, "mknod", syscall(__NR_mknod, (void *)(path), (mode_t)mode, (dev_t)dev));
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

	/* Parameter 1: res (type: PT_ERRNO)*/
	evt_test->assert_numeric_param(1, (uint64_t)errno_value);

	/* Parameter 2: uargs (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(2, path);

	/* Parameter 3: mode (type: PT_MODE) */
	evt_test->assert_numeric_param(3, mode);

	/* Parameter 4: dev (type: PT_UINT32) */
	evt_test->assert_numeric_param(4, 251658240);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);

}

TEST(SyscallExit, mknodX_failure_S_IFREG)
{
	auto evt_test = get_syscall_event_test(__NR_mknod, EXIT_EVENT);
	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	char path[] = "/tmp";

	mode_t mode = S_IXUSR | S_IFREG;
	uint32_t dev = 61440;
	assert_syscall_state(SYSCALL_FAILURE, "mknod", syscall(__NR_mknod, (void *)(path), (mode_t)mode, (dev_t)dev));
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

	/* Parameter 1: res (type: PT_ERRNO)*/
	evt_test->assert_numeric_param(1, (uint64_t)errno_value);

	/* Parameter 2: uargs (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(2, path);

	/* Parameter 3: mode (type: PT_MODE) */
	evt_test->assert_numeric_param(3, PPM_S_IXUSR | PPM_S_IFREG);

	/* Parameter 4: dev (type: PT_UINT32) */
	evt_test->assert_numeric_param(4, 251658240);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);

}

TEST(SyscallExit, mknodX_failure_S_IFCHR)
{
	auto evt_test = get_syscall_event_test(__NR_mknod, EXIT_EVENT);
	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	char path[] = "/tmp/";

	mode_t mode = S_IXUSR | S_IFCHR;
	uint32_t dev = 61440;
	assert_syscall_state(SYSCALL_FAILURE, "mknod", syscall(__NR_mknod, (void *)(path), (mode_t)mode, (dev_t)dev));
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

	/* Parameter 1: res (type: PT_ERRNO)*/
	evt_test->assert_numeric_param(1, (uint64_t)errno_value);

	/* Parameter 2: uargs (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(2, path);

	/* Parameter 3: mode (type: PT_MODE) */
	evt_test->assert_numeric_param(3, PPM_S_IXUSR | PPM_S_IFCHR);

	/* Parameter 4: dev (type: PT_UINT32) */
	evt_test->assert_numeric_param(4, 251658240);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);

}

TEST(SyscallExit, mknodX_failure_S_IFBLK)
{
	auto evt_test = get_syscall_event_test(__NR_mknod, EXIT_EVENT);
	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	char path[] = "/tmp/";

	mode_t mode = S_IXUSR | S_IFBLK;
	uint32_t dev = 61440;
	assert_syscall_state(SYSCALL_FAILURE, "mknod", syscall(__NR_mknod, (void *)(path), (mode_t)mode, (dev_t)dev));
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

	/* Parameter 1: res (type: PT_ERRNO)*/
	evt_test->assert_numeric_param(1, (uint64_t)errno_value);

	/* Parameter 2: uargs (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(2, path);

	/* Parameter 3: mode (type: PT_MODE) */
	evt_test->assert_numeric_param(3, PPM_S_IXUSR | PPM_S_IFBLK);

	/* Parameter 4: dev (type: PT_UINT32) */
	evt_test->assert_numeric_param(4, 251658240);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);

}

TEST(SyscallExit, mknodX_failure_S_IFIFO)
{
	auto evt_test = get_syscall_event_test(__NR_mknod, EXIT_EVENT);
	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	char path[] = "/tmp/";

	mode_t mode = S_IXUSR | S_IFIFO;
	uint32_t dev = 61440;
	assert_syscall_state(SYSCALL_FAILURE, "mknod", syscall(__NR_mknod, (void *)(path), (mode_t)mode, (dev_t)dev));
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

	/* Parameter 1: res (type: PT_ERRNO)*/
	evt_test->assert_numeric_param(1, (uint64_t)errno_value);

	/* Parameter 2: uargs (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(2, path);

	/* Parameter 3: mode (type: PT_MODE) */
	evt_test->assert_numeric_param(3, PPM_S_IXUSR | PPM_S_IFIFO);

	/* Parameter 4: dev (type: PT_UINT32) */
	evt_test->assert_numeric_param(4, 251658240);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);

}

TEST(SyscallExit, mknodX_failure_S_IFSOCK)
{
	auto evt_test = get_syscall_event_test(__NR_mknod, EXIT_EVENT);
	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	char path[] = "/tmp/";

	mode_t mode = S_IXUSR | S_IFSOCK;
	uint32_t dev = 61440;
	assert_syscall_state(SYSCALL_FAILURE, "mknod", syscall(__NR_mknod, (void *)(path), (mode_t)mode, (dev_t)dev));
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

	/* Parameter 1: res (type: PT_ERRNO)*/
	evt_test->assert_numeric_param(1, (uint64_t)errno_value);

	/* Parameter 2: uargs (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(2, path);

	/* Parameter 3: mode (type: PT_MODE) */
	evt_test->assert_numeric_param(3, PPM_S_IXUSR | PPM_S_IFSOCK);

	/* Parameter 4: dev (type: PT_UINT32) */
	evt_test->assert_numeric_param(4, 251658240);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);

}
#endif

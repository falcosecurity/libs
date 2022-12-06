#include "../../event_class/event_class.h"

#ifdef __NR_execveat
TEST(SyscallEnter, execveatE)
{
	auto evt_test = get_syscall_event_test(__NR_execveat, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/*
	 * If `dirfd` is `AT_FDCWD` then pathname is interpreted relative to
	 * the current working directory of the calling process. In our case
	 * there is no file `null-file-path` in this directory, so the call
	 * will fail!
	 */
	int dirfd = AT_FDCWD;
	char pathname[] = "//**null-file-path**//";
	const char* newargv = NULL;
	const char* newenviron = NULL;
	int flags = AT_SYMLINK_NOFOLLOW;
	assert_syscall_state(SYSCALL_FAILURE, "execveat", syscall(__NR_execveat, dirfd, pathname, newargv, newenviron, flags));

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

	/* Parameter 1: dirfd (type: PT_FD) */
	evt_test->assert_numeric_param(1, (int64_t)PPM_AT_FDCWD);

	/* Parameter 2: pathname (type: PT_FSRELPATH) */
	evt_test->assert_charbuf_param(2, pathname);

	/* Parameter 3: flags (type: PT_FLAGS32) */
	evt_test->assert_numeric_param(3, (uint32_t)PPM_EXVAT_AT_SYMLINK_NOFOLLOW);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}
#endif

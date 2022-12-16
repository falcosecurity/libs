#include "../../event_class/event_class.h"

#ifdef __NR_linkat
TEST(SyscallExit, linkatX)
{
	auto evt_test = get_syscall_event_test(__NR_linkat, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t old_fd = 7;
	int32_t new_fd = AT_FDCWD;
	const char* old_path = "/xyzk-this/is/the/old/path";
	const char* new_path = "/xyzk-this/is/the/new/path/";
	uint32_t flags = AT_SYMLINK_FOLLOW;
	assert_syscall_state(SYSCALL_FAILURE, "linkat", syscall(__NR_linkat, old_fd, old_path, new_fd, new_path, flags));
	int64_t errno_value = -errno;

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

	/* Parameter 2: olddirfd (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)old_fd);

	/* Parameter 3: oldpath (type: PT_FSRELPATH) */
	evt_test->assert_charbuf_param(3, old_path);

	/* Parameter 4: newdirfd (type: PT_FD) */
	evt_test->assert_numeric_param(4, (int64_t)PPM_AT_FDCWD);

	/* Parameter 5: newpath (type: PT_FSRELPATH) */
	evt_test->assert_charbuf_param(5, new_path);

	/* Parameter 6: flags (type: PT_FLAGS32) */
	evt_test->assert_numeric_param(6, (uint32_t)PPM_AT_SYMLINK_FOLLOW);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(6);
}
#endif

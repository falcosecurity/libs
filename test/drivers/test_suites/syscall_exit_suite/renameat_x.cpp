#include "../../event_class/event_class.h"

#ifdef __NR_renameat
TEST(SyscallExit, renameatX)
{
	auto evt_test = get_syscall_event_test(__NR_renameat, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* The 2 paths are invalid so the call will fail. */
	int32_t old_fd = 0;
	int32_t new_fd = AT_FDCWD;
	const char* old_path = "**//this/is/the/old/path";
	const char* new_path = "**//this/is/the/new/path/";
	assert_syscall_state(SYSCALL_FAILURE, "renameat", syscall(__NR_renameat, old_fd, old_path, new_fd, new_path));
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

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}
#endif

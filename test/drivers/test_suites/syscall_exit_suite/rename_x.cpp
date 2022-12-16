#include "../../event_class/event_class.h"

#ifdef __NR_rename
TEST(SyscallExit, renameX)
{
	auto evt_test = get_syscall_event_test(__NR_rename, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* The 2 paths are invalid so the call will fail. */
	const char* old_path = "**//this/is/the/old/path";
	const char* new_path = "**//this/is/the/new/path/";
	assert_syscall_state(SYSCALL_FAILURE, "rename", syscall(__NR_rename, old_path, new_path));
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

	/* Parameter 2: oldpath (type: PT_FSPATH) */
	evt_test->assert_charbuf_param(2, old_path);

	/* Parameter 3: newpath (type: PT_FSPATH) */
	evt_test->assert_charbuf_param(3, new_path);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}
#endif

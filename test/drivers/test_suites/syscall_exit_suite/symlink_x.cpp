#include "../../event_class/event_class.h"

#ifdef __NR_symlink
TEST(SyscallExit, symlinkX)
{
	auto evt_test = get_syscall_event_test(__NR_symlink, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	const char* target = "//**null-target**//";
	const char* path = "//**null-path**//";
	assert_syscall_state(SYSCALL_FAILURE, "symlink", syscall(__NR_symlink, target, path));
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

	/* Parameter 2: target (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(2, target);

	/* Parameter 3: linkpath (type: PT_FSPATH) */
	evt_test->assert_charbuf_param(3, path);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}
#endif

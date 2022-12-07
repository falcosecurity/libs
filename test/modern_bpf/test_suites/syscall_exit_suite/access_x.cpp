#include "../../event_class/event_class.h"

#ifdef __NR_access
TEST(SyscallExit, accessX)
{
	auto evt_test = get_syscall_event_test(__NR_access, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	const char* _pathname = "testfile";
	const int32_t _mode = W_OK;
	access(_pathname, _mode);
	assert_syscall_state(SYSCALL_FAILURE, "access", syscall(__NR_access, _pathname, _mode));
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

	/* Parameter 1: res (type: PT_ERRNO)*/
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/* Parameter 2: pathname (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(2, _pathname);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}
#endif

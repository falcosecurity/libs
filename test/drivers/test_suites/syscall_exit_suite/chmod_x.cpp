#include "../../event_class/event_class.h"

#ifdef __NR_chmod
TEST(SyscallExit, chmodX)
{
	auto evt_test = get_syscall_event_test(__NR_chmod, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	const char* filename = "*//null";
	uint32_t mode = S_IXUSR;
	assert_syscall_state(SYSCALL_FAILURE, "chmod", syscall(__NR_chmod, filename, mode));
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
	evt_test->assert_numeric_param(1, errno_value);

	/* Parameter 2: filename (type: PT_FSPATH) */
	evt_test->assert_charbuf_param(2, filename);

	/* Parameter 3: mode (type: PT_MODE) */
	evt_test->assert_numeric_param(3, PPM_S_IXUSR);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}
#endif

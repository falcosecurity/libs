#include "../../event_class/event_class.h"

#ifdef __NR_getcwd
TEST(SyscallExit, getcwdX_success)
{
	auto evt_test = get_syscall_event_test(__NR_getcwd, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	unsigned long size = 200;
	char path[size];
	uint32_t read_bytes = syscall(__NR_getcwd, path, size);
	assert_syscall_state(SYSCALL_SUCCESS, "getcwd", read_bytes, NOT_EQUAL, -1);

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
	/* returns the length of the buffer filled (which includes the ending '\0' character)
	 */
	evt_test->assert_numeric_param(1, (uint64_t)read_bytes);

	/* Parameter 2: path (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(2, path);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

TEST(SyscallExit, getcwdX_fail)
{
	auto evt_test = get_syscall_event_test(__NR_getcwd, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	long size = 2;
	char path[size];
	assert_syscall_state(SYSCALL_FAILURE, "getcwd", syscall(__NR_getcwd, path, size));
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
	evt_test->assert_numeric_param(1, (uint64_t)errno_value);

	/* Parameter 2: path (type: PT_CHARBUF) */
	evt_test->assert_empty_param(2);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}
#endif

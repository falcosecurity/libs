#include "../../event_class/event_class.h"

#include <sys/types.h>

#ifdef __NR_llseek
TEST(SyscallExit, llseekX)
{
	auto evt_test = get_syscall_event_test(__NR_llseek, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int fd = -1;
	unsigned long offset = (1 << 32) + 1;
	int whence = SEEK_SET;
	assert_syscall_state(SYSCALL_FAILURE, "llseek", syscall(__NR_llseek, fd, 1, 1, NULL, whence));
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

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif

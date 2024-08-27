#include "../../event_class/event_class.h"

#ifdef __NR_execve
TEST(SyscallEnter, execveE)
{
	auto evt_test = get_syscall_event_test(__NR_execve, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	char pathname[] = "//**null-file-path**//";
	const char *newargv = NULL;
	const char *newenviron = NULL;
	assert_syscall_state(SYSCALL_FAILURE, "execve", syscall(__NR_execve, pathname, newargv, newenviron));

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

	/* Parameter 1: pathname (type: PT_FSRELPATH) */
	evt_test->assert_charbuf_param(1, pathname);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif

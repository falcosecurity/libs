#include "../../event_class/event_class.h"

#ifdef __NR_stat

TEST(SyscallEnter, statE)
{
	auto evt_test = get_syscall_event_test(__NR_stat, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	char pathname[] = "//**null-file-path**//";
	struct stat statbuf = {};
	assert_syscall_state(SYSCALL_FAILURE, "stat", syscall(__NR_stat, pathname, &statbuf));

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


	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(0);
}
#endif

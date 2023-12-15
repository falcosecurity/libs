#include "../../event_class/event_class.h"

#ifdef __NR_clone3

#include <linux/sched.h>

TEST(SyscallEnter, clone3E)
{
	auto evt_test = get_syscall_event_test(__NR_clone3, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* flags are invalid so the syscall will fail. */
	clone_args cl_args = {0};
	cl_args.flags = (unsigned long)-1;
	assert_syscall_state(SYSCALL_FAILURE, "clone3", syscall(__NR_clone3, &cl_args, sizeof(cl_args)));

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

	// Here we have no parameters to assert.

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(0);
}
#endif

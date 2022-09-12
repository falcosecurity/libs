#include "../../event_class/event_class.h"

#ifdef __NR_symlinkat
TEST(SyscallEnter, symlinkatE)
{
	auto evt_test = get_syscall_event_test(__NR_symlinkat, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	const char* target = NULL;
	int32_t mock_dirfd = 0;
	const char* path = NULL;
	assert_syscall_state(SYSCALL_FAILURE, "symlinkat", syscall(__NR_symlinkat, target, mock_dirfd, path));

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

	// Here we have no parameters to assert.

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(0);
}
#endif

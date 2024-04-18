#include "../../event_class/event_class.h"

#ifdef __NR_unlinkat
TEST(SyscallEnter, unlinkatE)
{
	auto evt_test = get_syscall_event_test(__NR_unlinkat, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t mock_dirfd = 0;
	const char* path = NULL;
	uint32_t flags = 0;
	assert_syscall_state(SYSCALL_FAILURE, "unlinkat", syscall(__NR_unlinkat, mock_dirfd, path, flags));

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

#include "../../event_class/event_class.h"

#ifdef __NR_linkat
TEST(SyscallEnter, linkatE)
{
	auto evt_test = get_syscall_event_test(__NR_linkat, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t old_fd = 0;
	int32_t new_fd = 0;
	const char* old_path = NULL;
	const char* new_path = NULL;
	uint32_t flags = 0;
	assert_syscall_state(SYSCALL_FAILURE, "linkat", syscall(__NR_linkat, old_fd, old_path, new_fd, new_path, flags));

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

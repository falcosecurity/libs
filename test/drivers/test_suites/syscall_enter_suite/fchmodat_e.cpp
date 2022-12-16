#include "../../event_class/event_class.h"

#ifdef __NR_fchmodat
TEST(SyscallEnter, fchmodatE)
{
	auto evt_test = get_syscall_event_test(__NR_fchmodat, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t mock_dirfd = 0;
	const char* pathname = NULL;
	uint32_t mode = 0;
	uint32_t flags = 0;
	assert_syscall_state(SYSCALL_FAILURE, "fchmodat", syscall(__NR_fchmodat, mock_dirfd, pathname, mode, flags));

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

#include "../../event_class/event_class.h"

#ifdef __NR_newfstatat
TEST(SyscallEnter, newfstatatE)
{
	auto evt_test = get_syscall_event_test(__NR_newfstatat, ENTER_EVENT);
	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	//int dirfd = AT_FDCWD;
	int dirfd = -1;
	const char* pathname = "mock_path";
	struct stat buffer;
	int flags = AT_EMPTY_PATH | AT_NO_AUTOMOUNT | AT_SYMLINK_NOFOLLOW;

	assert_syscall_state(SYSCALL_FAILURE, "newfstatat", syscall(__NR_newfstatat, dirfd, pathname, &buffer, flags));


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
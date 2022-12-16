#include "../../event_class/event_class.h"

#ifdef __NR_setsockopt

#include <netdb.h>

TEST(SyscallEnter, setsockoptE)
{
	auto evt_test = get_syscall_event_test(__NR_setsockopt, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int socket_fd = 0;
	int level = 0;
	int option_name = 0;
	const void* option_value = NULL;
	socklen_t option_len = 0;
	assert_syscall_state(SYSCALL_FAILURE, "setsockopt", syscall(__NR_setsockopt, socket_fd, level, option_name, option_value, option_len));

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

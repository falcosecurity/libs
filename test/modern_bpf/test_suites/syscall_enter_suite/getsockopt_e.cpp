#include "../../event_class/event_class.h"

#ifdef __NR_getsockopt

#include <netdb.h>

TEST(SyscallEnter, getsockoptE)
{
	auto evt_test = get_syscall_event_test(__NR_getsockopt, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int socket_fd = 0;
	int level = 0;
	int option_name = 0;
	int option_value = 0;
	socklen_t option_len = 0;
	assert_syscall_state(SYSCALL_FAILURE, "getsockopt", syscall(__NR_getsockopt, socket_fd, level, option_name, &option_value, &option_len));

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

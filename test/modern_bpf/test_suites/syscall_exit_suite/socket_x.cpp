#include "../../event_class/event_class.h"

#if defined(__NR_socket) && defined(__NR_close)

#include <sys/socket.h>

TEST(SyscallExit, socketX)
{
	auto evt_test = get_syscall_event_test(__NR_socket, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int domain = AF_INET;
	int type = SOCK_RAW;
	int protocol = PF_INET;
	int32_t socket_fd = syscall(__NR_socket, domain, type, protocol);
	assert_syscall_state(SYSCALL_SUCCESS, "socket_fd", socket_fd, NOT_EQUAL, -1);
	syscall(__NR_close, socket_fd);

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

	/* Parameter 1: res (type: PT_ERRNO)*/
	evt_test->assert_numeric_param(1, (int64_t)socket_fd);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif

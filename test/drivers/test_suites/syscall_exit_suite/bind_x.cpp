#include "../../event_class/event_class.h"

#if defined(__NR_bind) && defined(__NR_setsockopt) && defined(__NR_socket) && defined(__NR_close)

#include <sys/un.h>

TEST(SyscallExit, bindX_INET)
{
	auto evt_test = get_syscall_event_test(__NR_bind, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t server_socket_fd = syscall(__NR_socket, AF_INET, SOCK_DGRAM, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "socket", server_socket_fd, NOT_EQUAL, -1);
	evt_test->server_reuse_address_port(server_socket_fd);

	sockaddr_in server_addr;
	evt_test->server_fill_sockaddr_in(&server_addr);

	assert_syscall_state(SYSCALL_SUCCESS, "bind", syscall(__NR_bind, server_socket_fd, (sockaddr*)&server_addr, sizeof(server_addr)), NOT_EQUAL, -1);

	/* Cleaning phase */
	syscall(__NR_close, server_socket_fd);

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

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)0);

	/* Parameter 2: addr (type: PT_SOCKADDR) */
	evt_test->assert_addr_info_inet_param(2, PPM_AF_INET, IPV4_SERVER, IPV4_PORT_SERVER_STRING);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

TEST(SyscallExit, bindX_INET6)
{
	auto evt_test = get_syscall_event_test(__NR_bind, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t server_socket_fd = syscall(__NR_socket, AF_INET6, SOCK_DGRAM, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "socket", server_socket_fd, NOT_EQUAL, -1);
	evt_test->server_reuse_address_port(server_socket_fd);

	sockaddr_in6 server_addr;
	evt_test->server_fill_sockaddr_in6(&server_addr);

	assert_syscall_state(SYSCALL_SUCCESS, "bind", syscall(__NR_bind, server_socket_fd, (sockaddr*)&server_addr, sizeof(server_addr)), NOT_EQUAL, -1);

	/* Cleaning phase */
	syscall(__NR_close, server_socket_fd);

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

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)0);

	/* Parameter 2: addr (type: PT_SOCKADDR) */
	evt_test->assert_addr_info_inet6_param(2, PPM_AF_INET6, IPV6_SERVER, IPV6_PORT_SERVER_STRING);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

#ifdef __NR_unlinkat
TEST(SyscallExit, bindX_UNIX)
{
	auto evt_test = get_syscall_event_test(__NR_bind, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t server_socket_fd = syscall(__NR_socket, AF_UNIX, SOCK_DGRAM, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "socket", server_socket_fd, NOT_EQUAL, -1);

	struct sockaddr_un server_addr;
	evt_test->server_fill_sockaddr_un(&server_addr);

	assert_syscall_state(SYSCALL_SUCCESS, "bind", syscall(__NR_bind, server_socket_fd, (sockaddr*)&server_addr, sizeof(server_addr)), NOT_EQUAL, -1);

	/* Cleaning phase */
	syscall(__NR_close, server_socket_fd);
	syscall(__NR_unlinkat, 0, UNIX_SERVER, 0);

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

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)0);

	/* Parameter 2: addr (type: PT_SOCKADDR) */
	evt_test->assert_addr_info_unix_param(2, PPM_AF_UNIX, UNIX_SERVER);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}
#endif /* __NR_unlinkat */

TEST(SyscallExit, bindX_failure)
{
	auto evt_test = get_syscall_event_test(__NR_bind, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t mock_fd = -1;
	sockaddr* addr = NULL;
	socklen_t addrlen = 0;
	assert_syscall_state(SYSCALL_FAILURE, "bind", syscall(__NR_bind, mock_fd, addr, addrlen));
	int64_t errno_value = -errno;

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

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/* Parameter 2: addr (type: PT_SOCKADDR) */
	/* Since the pointer to the `sockaddr` is `NULL` we expect an empty param here. */
	evt_test->assert_empty_param(2);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

#endif

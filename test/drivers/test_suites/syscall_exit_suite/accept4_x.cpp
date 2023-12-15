#include "../../event_class/event_class.h"

#if defined(__NR_accept4) && defined(__NR_connect) && defined(__NR_socket) && defined(__NR_bind) && defined(__NR_listen) && defined(__NR_close) && defined(__NR_setsockopt) && defined(__NR_shutdown)

/* On `s390x` architectures only `accept4` (`accept` is not defined) is used so we need to test all the cases also here. */

TEST(SyscallExit, accept4X_INET)
{
	auto evt_test = get_syscall_event_test(__NR_accept4, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_socket_fd = 0;
	int32_t server_socket_fd = 0;
	sockaddr_in client_addr = {0};
	sockaddr_in server_addr = {0};
	evt_test->connect_ipv4_client_to_server(&client_socket_fd, &client_addr, &server_socket_fd, &server_addr);

	/* We don't want to get any info about the connected socket so `addr` and `addrlen` are NULL. */
	sockaddr* addr = NULL;
	socklen_t *addrlen = NULL;
	int flags = 0;
	int connected_socket_fd = syscall(__NR_accept4, server_socket_fd, addr, addrlen, flags);
	assert_syscall_state(SYSCALL_SUCCESS, "accept4 (server)", connected_socket_fd, NOT_EQUAL, -1);

	/* Cleaning phase */
	syscall(__NR_shutdown, connected_socket_fd, 2);
	syscall(__NR_shutdown, server_socket_fd, 2);
	syscall(__NR_shutdown, client_socket_fd, 2);
	syscall(__NR_close, connected_socket_fd);
	syscall(__NR_close, server_socket_fd);
	syscall(__NR_close, client_socket_fd);

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

	/* Parameter 1: fd (type: PT_FD) */
	evt_test->assert_numeric_param(1, (int64_t)connected_socket_fd);

	/* Parameter 2: tuple (type: PT_SOCKTUPLE) */
	/* The server performs an `accept` so the `client` is the src. */
	evt_test->assert_tuple_inet_param(2, PPM_AF_INET, IPV4_CLIENT, IPV4_SERVER, IPV4_PORT_CLIENT_STRING, IPV4_PORT_SERVER_STRING);

	/* Parameter 3: queuepct (type: PT_UINT8) */
	/* we expect 0 elements in the queue so 0%. */
	evt_test->assert_numeric_param(3, (uint8_t)0);

	/* Parameter 4: queuelen (type: PT_UINT32) */
	/* we expect 0 elements. */
	evt_test->assert_numeric_param(4, (uint32_t)0);

	/* Parameter 5: queuemax (type: PT_UINT32) */
	evt_test->assert_numeric_param(5, (uint32_t)QUEUE_LENGTH);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

TEST(SyscallExit, accept4X_INET6)
{
	auto evt_test = get_syscall_event_test(__NR_accept4, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_socket_fd = 0;
	int32_t server_socket_fd = 0;
	sockaddr_in6 client_addr = {0};
	sockaddr_in6 server_addr = {0};
	evt_test->connect_ipv6_client_to_server(&client_socket_fd, &client_addr, &server_socket_fd, &server_addr);

	/* We don't want to get any info about the connected socket so `addr` and `addrlen` are NULL. */
	sockaddr* addr = NULL;
	socklen_t *addrlen = NULL;
	int flags = 0;
	int connected_socket_fd = syscall(__NR_accept4, server_socket_fd, addr, addrlen, flags);
	assert_syscall_state(SYSCALL_SUCCESS, "accept4 (server)", connected_socket_fd, NOT_EQUAL, -1);

	/* Cleaning phase */
	syscall(__NR_shutdown, connected_socket_fd, 2);
	syscall(__NR_shutdown, server_socket_fd, 2);
	syscall(__NR_shutdown, client_socket_fd, 2);
	syscall(__NR_close, connected_socket_fd);
	syscall(__NR_close, server_socket_fd);
	syscall(__NR_close, client_socket_fd);

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

	/* Parameter 1: fd (type: PT_FD) */
	evt_test->assert_numeric_param(1, (int64_t)connected_socket_fd);

	/* Parameter 2: tuple (type: PT_SOCKTUPLE) */
	/* The server performs an `accept` so the `client` is the src. */
	evt_test->assert_tuple_inet6_param(2, PPM_AF_INET6, IPV6_CLIENT, IPV6_SERVER, IPV6_PORT_CLIENT_STRING, IPV6_PORT_SERVER_STRING);

	/* Parameter 3: queuepct (type: PT_UINT8) */
	/* we expect 0 elements in the queue so 0%. */
	evt_test->assert_numeric_param(3, (uint8_t)0);

	/* Parameter 4: queuelen (type: PT_UINT32) */
	/* we expect 0 elements. */
	evt_test->assert_numeric_param(4, (uint32_t)0);

	/* Parameter 5: queuemax (type: PT_UINT32) */
	evt_test->assert_numeric_param(5, (uint32_t)QUEUE_LENGTH);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

#ifdef __NR_unlinkat
TEST(SyscallExit, accept4X_UNIX)
{
	auto evt_test = get_syscall_event_test(__NR_accept4, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_socket_fd = 0;
	int32_t server_socket_fd = 0;
	struct sockaddr_un client_addr = {0};
	struct sockaddr_un server_addr = {0};
	evt_test->connect_unix_client_to_server(&client_socket_fd, &client_addr, &server_socket_fd, &server_addr);

	/* We don't want to get any info about the connected socket so `addr` and `addrlen` are NULL. */
	sockaddr* addr = NULL;
	socklen_t *addrlen = NULL;
	int flags = 0;
	int connected_socket_fd = syscall(__NR_accept4, server_socket_fd, addr, addrlen, flags);
	assert_syscall_state(SYSCALL_SUCCESS, "accept4 (server)", connected_socket_fd, NOT_EQUAL, -1);

	/* Cleaning phase */
	syscall(__NR_shutdown, connected_socket_fd, 2);
	syscall(__NR_shutdown, server_socket_fd, 2);
	syscall(__NR_shutdown, client_socket_fd, 2);
	syscall(__NR_close, connected_socket_fd);
	syscall(__NR_close, server_socket_fd);
	syscall(__NR_close, client_socket_fd);
	syscall(__NR_unlinkat, 0, UNIX_CLIENT, 0);
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

	/* Parameter 1: fd (type: PT_FD) */
	evt_test->assert_numeric_param(1, (int64_t)connected_socket_fd);

	/* Parameter 2: tuple (type: PT_SOCKTUPLE) */
	/* The server performs an `accept` so the `client` is the src. */
	evt_test->assert_tuple_unix_param(2, PPM_AF_UNIX, UNIX_SERVER);

	/* Parameter 3: queuepct (type: PT_UINT8) */
	/* we expect 0 elements in the queue so 0%. */
	evt_test->assert_numeric_param(3, (uint8_t)0);

	/* Parameter 4: queuelen (type: PT_UINT32) */
	/* we expect 0 elements. */
	evt_test->assert_numeric_param(4, (uint32_t)0);

	/* Parameter 5: queuemax (type: PT_UINT32) */
	evt_test->assert_numeric_param(5, (uint32_t)QUEUE_LENGTH);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}
#endif /* __NR_unlinkat */

TEST(SyscallExit, accept4X_failure)
{
	auto evt_test = get_syscall_event_test(__NR_accept4, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t mock_fd = -1;
	sockaddr* addr = NULL;
	socklen_t *addrlen = NULL;
	int flags = 0;
	assert_syscall_state(SYSCALL_FAILURE, "accept4", syscall(__NR_accept4, mock_fd, addr, addrlen, flags));
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

	/* Parameter 1: fd (type: PT_FD) */
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/* Parameter 2: tuple (type: PT_SOCKTUPLE) */
	evt_test->assert_empty_param(2);

	/* Parameter 3: queuepct (type: PT_UINT8) */
	evt_test->assert_numeric_param(3, (uint8_t)0);

	/* Parameter 4: queuelen (type: PT_UINT32) */
	evt_test->assert_numeric_param(4, (uint32_t)0);

	/* Parameter 5: queuemax (type: PT_UINT32) */
	evt_test->assert_numeric_param(5, (uint32_t)0);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}
#endif

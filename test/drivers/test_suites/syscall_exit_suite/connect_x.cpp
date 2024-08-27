#include "../../event_class/event_class.h"

#if defined(__NR_connect) && defined(__NR_socket) && defined(__NR_bind) && defined(__NR_close)

#include <netdb.h>
#include <sys/un.h>

TEST(SyscallExit, connectX_INET)
{
	auto evt_test = get_syscall_event_test(__NR_connect, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t client_socket_fd = syscall(__NR_socket, AF_INET, SOCK_DGRAM, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "socket (client)", client_socket_fd, NOT_EQUAL, -1);
	evt_test->client_reuse_address_port(client_socket_fd);

	sockaddr_in client_addr;
	evt_test->client_fill_sockaddr_in(&client_addr);

	/* We need to bind the client socket with an address otherwise we cannot assert against it. */
	assert_syscall_state(SYSCALL_SUCCESS, "bind (client)", syscall(__NR_bind, client_socket_fd, (sockaddr*)&client_addr, sizeof(client_addr)), NOT_EQUAL, -1);

	/* Now we associate the client socket with the server address. */
	sockaddr_in server_addr;
	evt_test->server_fill_sockaddr_in(&server_addr);

	/* With `SOCK_DGRAM` the `connect` will not perform a connection this is why the syscall doesn't fail. */
	assert_syscall_state(SYSCALL_SUCCESS, "connect (client)", syscall(__NR_connect, client_socket_fd, (sockaddr*)&server_addr, sizeof(server_addr)), NOT_EQUAL, -1);

	/* Cleaning phase */
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

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)0);

	/* Parameter 2: tuple (type: PT_SOCKTUPLE) */
	/* The client performs a `connect` so the client is the src. */
	evt_test->assert_tuple_inet_param(2, PPM_AF_INET, IPV4_CLIENT, IPV4_SERVER, IPV4_PORT_CLIENT_STRING, IPV4_PORT_SERVER_STRING);

	/* Parameter 3: fd (type: PT_FD) */
	evt_test->assert_numeric_param(3, (int64_t)client_socket_fd);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}

TEST(SyscallExit, connectX_INET6)
{
	auto evt_test = get_syscall_event_test(__NR_connect, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t client_socket_fd = syscall(__NR_socket, AF_INET6, SOCK_DGRAM, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "socket (client)", client_socket_fd, NOT_EQUAL, -1);
	evt_test->client_reuse_address_port(client_socket_fd);

	sockaddr_in6 client_addr;
	evt_test->client_fill_sockaddr_in6(&client_addr);

	/* We need to bind the client socket with an address otherwise we cannot assert against it. */
	assert_syscall_state(SYSCALL_SUCCESS, "bind (client)", syscall(__NR_bind, client_socket_fd, (sockaddr*)&client_addr, sizeof(client_addr)), NOT_EQUAL, -1);

	sockaddr_in6 server_addr;
	evt_test->server_fill_sockaddr_in6(&server_addr);

	/* Now we associate the client socket with the server address. */
	assert_syscall_state(SYSCALL_SUCCESS, "connect (client)", syscall(__NR_connect, client_socket_fd, (sockaddr*)&server_addr, sizeof(server_addr)), NOT_EQUAL, -1);

	/* Cleaning phase */
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

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)0);

	/* Parameter 2: tuple (type: PT_SOCKTUPLE) */
	/* The client performs a `connect` so the client is the src. */
	evt_test->assert_tuple_inet6_param(2, PPM_AF_INET6, IPV6_CLIENT, IPV6_SERVER, IPV6_PORT_CLIENT_STRING, IPV6_PORT_SERVER_STRING);

	/* Parameter 3: fd (type: PT_FD) */
	evt_test->assert_numeric_param(3, (int64_t)client_socket_fd);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}

#ifdef __NR_unlinkat
TEST(SyscallExit, connectX_UNIX)
{
	auto evt_test = get_syscall_event_test(__NR_connect, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t client_socket_fd = syscall(__NR_socket, AF_UNIX, SOCK_DGRAM, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "socket (client)", client_socket_fd, NOT_EQUAL, -1);

	struct sockaddr_un client_addr;
	evt_test->client_fill_sockaddr_un(&client_addr);

	/* We need to bind the client socket with an address otherwise we cannot assert against it. */
	assert_syscall_state(SYSCALL_SUCCESS, "bind (client)", syscall(__NR_bind, client_socket_fd, (sockaddr*)&client_addr, sizeof(client_addr)), NOT_EQUAL, -1);

	/* We need to create a server socket. */
	int32_t server_socket_fd = syscall(__NR_socket, AF_UNIX, SOCK_DGRAM, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "socket (server)", server_socket_fd, NOT_EQUAL, -1);

	struct sockaddr_un server_addr;
	evt_test->server_fill_sockaddr_un(&server_addr);

	assert_syscall_state(SYSCALL_SUCCESS, "bind (server)", syscall(__NR_bind, server_socket_fd, (sockaddr*)&server_addr, sizeof(server_addr)), NOT_EQUAL, -1);

	assert_syscall_state(SYSCALL_SUCCESS, "connect (client)", syscall(__NR_connect, client_socket_fd, (sockaddr*)&server_addr, sizeof(server_addr)), NOT_EQUAL, -1);

	/* Cleaning phase */
	syscall(__NR_close, client_socket_fd);
	syscall(__NR_close, server_socket_fd);
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

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)0);

	/* Parameter 2: tuple (type: PT_SOCKTUPLE) */
	/* The client performs a `connect` so the client is the src. */
	evt_test->assert_tuple_unix_param(2, PPM_AF_UNIX, UNIX_SERVER);

	/* Parameter 3: fd (type: PT_FD) */
	evt_test->assert_numeric_param(3, (int64_t)client_socket_fd);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}
#endif /* __NR_unlinkat */

TEST(SyscallExit, connectX_failure)
{
	auto evt_test = get_syscall_event_test(__NR_connect, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t mock_fd = -1;
	const sockaddr* addr = NULL;
	socklen_t addrlen = 0;
	assert_syscall_state(SYSCALL_FAILURE, "connect", syscall(__NR_connect, mock_fd, addr, addrlen));
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
	evt_test->assert_numeric_param(1, errno_value);

	/* Parameter 2: tuple (type: PT_SOCKTUPLE) */
	evt_test->assert_empty_param(2);

	/* Parameter 3: fd (type: PT_FD) */
	evt_test->assert_numeric_param(3, (int64_t)mock_fd);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}

TEST(SyscallExit, connectX_failure_ECONNREFUSED)
{
	auto evt_test = get_syscall_event_test(__NR_connect, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/
	/* The socket here is blocking so the errno will be ECONNREFUSED */
	int32_t client_socket_fd = syscall(__NR_socket, AF_INET, SOCK_STREAM, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "socket (client)", client_socket_fd, NOT_EQUAL, -1);
	evt_test->client_reuse_address_port(client_socket_fd);

	sockaddr_in client_addr;
	evt_test->client_fill_sockaddr_in(&client_addr);

	/* We need to bind the client socket with an address otherwise we cannot assert against it. */
	assert_syscall_state(SYSCALL_SUCCESS, "bind (client)", syscall(__NR_bind, client_socket_fd, (sockaddr*)&client_addr, sizeof(client_addr)), NOT_EQUAL, -1);

	/* We try to reach this server that doesn't exist */
	sockaddr_in server_addr;
	evt_test->server_fill_sockaddr_in(&server_addr);

	assert_syscall_state(SYSCALL_FAILURE, "connect (client)", syscall(__NR_connect, client_socket_fd, (sockaddr*)&server_addr, sizeof(server_addr)));

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
	evt_test->assert_numeric_param(1, (int64_t)-ECONNREFUSED);

	/* Parameter 2: tuple (type: PT_SOCKTUPLE) */
	/* Modern BPF doesn't return the tuple in case of failure */
	if(evt_test->is_modern_bpf_engine())
	{
		evt_test->assert_empty_param(2);
	}
	else
	{
		evt_test->assert_tuple_inet_param(2, PPM_AF_INET, IPV4_CLIENT, IPV4_SERVER, IPV4_PORT_CLIENT_STRING, IPV4_PORT_SERVER_STRING);
	}

	/* Parameter 3: fd (type: PT_FD) */
	evt_test->assert_numeric_param(3, (int64_t)client_socket_fd);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}

TEST(SyscallExit, connectX_failure_EINPROGRESS)
{
	auto evt_test = get_syscall_event_test(__NR_connect, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	/* The socket here is not blocking so the errno will be EINPROGRESS */
	int32_t client_socket_fd = syscall(__NR_socket, AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "socket (client)", client_socket_fd, NOT_EQUAL, -1);
	evt_test->client_reuse_address_port(client_socket_fd);

	sockaddr_in client_addr;
	evt_test->client_fill_sockaddr_in(&client_addr);

	assert_syscall_state(SYSCALL_SUCCESS, "bind (client)", syscall(__NR_bind, client_socket_fd, (sockaddr*)&client_addr, sizeof(client_addr)), NOT_EQUAL, -1);

	int32_t server_socket_fd = syscall(__NR_socket, AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "socket (server)", server_socket_fd, NOT_EQUAL, -1);
	evt_test->server_reuse_address_port(server_socket_fd);

	sockaddr_in server_addr;
	evt_test->server_fill_sockaddr_in(&server_addr);

	/* Now we bind the server socket with the server address. */
	assert_syscall_state(SYSCALL_SUCCESS, "bind (server)", syscall(__NR_bind, server_socket_fd, (sockaddr*)&server_addr, sizeof(server_addr)), NOT_EQUAL, -1);

	/* Here we don't call listen so the connection from the client should be
	 * in progress.
	 */

	assert_syscall_state(SYSCALL_FAILURE, "connect (client)", syscall(__NR_connect, client_socket_fd, (sockaddr*)&server_addr, sizeof(server_addr)));

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
	evt_test->assert_numeric_param(1, (int64_t)-EINPROGRESS);

	/* Parameter 2: tuple (type: PT_SOCKTUPLE) */
	/* `EINPROGRESS` is the unique failure case that the modern bpf probe
	 * can catch.
	 */
	evt_test->assert_tuple_inet_param(2, PPM_AF_INET, IPV4_CLIENT, IPV4_SERVER, IPV4_PORT_CLIENT_STRING, IPV4_PORT_SERVER_STRING);

	/* Parameter 3: fd (type: PT_FD) */
	evt_test->assert_numeric_param(3, (int64_t)client_socket_fd);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}
#endif

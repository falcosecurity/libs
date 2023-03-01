#include "../../event_class/event_class.h"

#if defined(__NR_socketcall) && defined(__NR_socket) && defined(__NR_bind) && defined(__NR_connect)

#include <sys/socket.h>
#include <linux/net.h>

#if defined(__NR_clone3) && defined(__NR_wait4)
#include <linux/sched.h>

TEST(SyscallExit, socketcall_socketX)
{
	auto evt_test = get_syscall_event_test(__NR_socket, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	unsigned long args[3] = {0};
	args[0] = -1;
	args[1] = -1;
	args[2] = -1;

	/* Here we need to call the `socket` from a child because the main process throws a `socket`
	 * syscall to calibrate the socket file options if we are using the bpf probe.
	 */
	struct clone_args cl_args = {0};
	cl_args.flags = CLONE_FILES;
	cl_args.exit_signal = SIGCHLD;
	pid_t ret_pid = syscall(__NR_clone3, &cl_args, sizeof(cl_args));

	if(ret_pid == 0)
	{
		/* In this way in the father we know if the call was successful or not. */
		if(syscall(__NR_socketcall, SYS_SOCKET, args) == -1)
		{
			exit(EXIT_SUCCESS);
		}
		else
		{
			exit(EXIT_FAILURE);
		}
	}

	assert_syscall_state(SYSCALL_SUCCESS, "clone3", ret_pid, NOT_EQUAL, -1);
	/* Catch the child before doing anything else. */
	int status = 0;
	int options = 0;
	assert_syscall_state(SYSCALL_SUCCESS, "wait4", syscall(__NR_wait4, ret_pid, &status, options, NULL), NOT_EQUAL, -1);

	if(__WEXITSTATUS(status) == EXIT_FAILURE || __WIFSIGNALED(status) != 0)
	{
		FAIL() << "The 'socketcall socket' is successful while it should fail..." << std::endl;
	}

	/* This is the errno value we expect from the `socket` call. */
	int64_t errno_value = -EINVAL;

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence(ret_pid);

	if(HasFatalFailure())
	{
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO)*/
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif

TEST(SyscallExit, socketcall_bindX)
{
	auto evt_test = get_syscall_event_test(__NR_bind, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t server_socket_fd = syscall(__NR_socket, AF_INET, SOCK_DGRAM, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "socket", server_socket_fd, NOT_EQUAL, -1);
	evt_test->server_reuse_address_port(server_socket_fd);

	struct sockaddr_in server_addr;
	evt_test->server_fill_sockaddr_in(&server_addr);

	unsigned long args[3] = {0};
	args[0] = server_socket_fd;
	args[1] = (unsigned long)&server_addr;
	args[2] = sizeof(server_addr);

	assert_syscall_state(SYSCALL_SUCCESS, "bind", syscall(__NR_socketcall, SYS_BIND, args), NOT_EQUAL, -1);

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

TEST(SyscallExit, socketcall_connectX)
{
	auto evt_test = get_syscall_event_test(__NR_connect, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t client_socket_fd = syscall(__NR_socket, AF_INET, SOCK_DGRAM, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "socket (client)", client_socket_fd, NOT_EQUAL, -1);
	evt_test->client_reuse_address_port(client_socket_fd);

	struct sockaddr_in client_addr;
	evt_test->client_fill_sockaddr_in(&client_addr);

	/* We need to bind the client socket with an address otherwise we cannot assert against it. */
	assert_syscall_state(SYSCALL_SUCCESS, "bind (client)", syscall(__NR_bind, client_socket_fd, (struct sockaddr *)&client_addr, sizeof(client_addr)), NOT_EQUAL, -1);

	/* Now we associate the client socket with the server address. */
	struct sockaddr_in server_addr;
	evt_test->server_fill_sockaddr_in(&server_addr);

	/* With `SOCK_DGRAM` the `connect` will not perform a connection this is why the syscall doesn't fail. */
	unsigned long args[3] = {0};
	args[0] = client_socket_fd;
	args[1] = (unsigned long)&server_addr;
	args[2] = sizeof(server_addr);
	assert_syscall_state(SYSCALL_SUCCESS, "socketcall connect (client)", syscall(__NR_socketcall, SYS_CONNECT, args), NOT_EQUAL, -1);

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

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}
#endif

#ifdef __NR_recvmmsg
TEST(SyscallExit, socketcall_recvmmsgX)
{
	auto evt_test = get_syscall_event_test(__NR_recvmmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t mock_fd = -1;
	struct msghdr *msg = NULL;
	uint32_t vlen = 0;
	int flags = 0;
	struct timespec *timeout = NULL;

	unsigned long args[5] = {0};
	args[0] = mock_fd;
	args[1] = (unsigned long)msg;
	args[2] = vlen;
	args[3] = flags;
	args[4] = (unsigned long)timeout;
	assert_syscall_state(SYSCALL_FAILURE, "recvmmsg", syscall(__NR_socketcall, SYS_RECVMMSG, args));

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

#ifdef __NR_sendmmsg
TEST(SyscallExit, socketcall_sendmmsgX)
{
	auto evt_test = get_syscall_event_test(__NR_sendmmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t mock_fd = -1;
	struct msghdr *msg = NULL;
	uint32_t vlen = 0;
	int flags = 0;

	unsigned long args[4] = {0};
	args[0] = mock_fd;
	args[1] = (unsigned long)msg;
	args[2] = vlen;
	args[3] = flags;
	assert_syscall_state(SYSCALL_FAILURE, "sendmmsg", syscall(__NR_socketcall, SYS_SENDMMSG, args));

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

TEST(SyscallExit, socketcall_shutdownX)
{
	auto evt_test = get_syscall_event_test(__NR_shutdown, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t invalid_fd = -1;
	int how = SHUT_RD;

	unsigned long args[2] = {0};
	args[0] = invalid_fd;
	args[1] = how;
	assert_syscall_state(SYSCALL_FAILURE, "shutdown", syscall(__NR_socketcall, SYS_SHUTDOWN, args));
	int64_t errno_value = -errno;

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

	/* Parameter 1: ret (type: PT_FD)*/
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}

#if defined(__NR_accept) || defined(__s390x__)

#if defined(__NR_connect) && defined(__NR_socket) && defined(__NR_bind) && defined(__NR_listen) && defined(__NR_close) && defined(__NR_setsockopt) && defined(__NR_shutdown)

TEST(SyscallExit, socketcall_acceptX_INET)
{
#ifdef __s390x__
	auto evt_test = get_syscall_event_test(__NR_accept4, EXIT_EVENT);
	if(evt_test->is_kmod_engine())
		GTEST_SKIP() << "[acceptX] kmod socketcall implementation is event based (rather syscall) " << std::endl;
#else
	auto evt_test = get_syscall_event_test(__NR_accept, EXIT_EVENT);
#endif

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_socket_fd = 0;
	int32_t server_socket_fd = 0;
	struct sockaddr_in client_addr = {0};
	struct sockaddr_in server_addr = {0};
	evt_test->connect_ipv4_client_to_server(&client_socket_fd, &client_addr, &server_socket_fd, &server_addr);

	/* We don't want to get any info about the connected socket so `addr` and `addrlen` are NULL. */
	unsigned long args[3] = {0};
	args[0] = server_socket_fd;
	args[1] = (unsigned long)NULL;
	args[2] = (unsigned long)NULL;
	int connected_socket_fd = syscall(__NR_socketcall, SYS_ACCEPT, args);
	assert_syscall_state(SYSCALL_SUCCESS, "accept (server)", connected_socket_fd, NOT_EQUAL, -1);

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

TEST(SyscallExit, socketcall_acceptX_INET6)
{
#ifdef __s390x__
	auto evt_test = get_syscall_event_test(__NR_accept4, EXIT_EVENT);
	if(evt_test->is_kmod_engine())
		GTEST_SKIP() << "[acceptX] kmod socketcall implementation is event based (rather syscall) " << std::endl;
#else
	auto evt_test = get_syscall_event_test(__NR_accept, EXIT_EVENT);
#endif

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_socket_fd = 0;
	int32_t server_socket_fd = 0;
	struct sockaddr_in6 client_addr = {0};
	struct sockaddr_in6 server_addr = {0};
	evt_test->connect_ipv6_client_to_server(&client_socket_fd, &client_addr, &server_socket_fd, &server_addr);

	/* We don't want to get any info about the connected socket so `addr` and `addrlen` are NULL. */
	unsigned long args[3] = {0};
	args[0] = server_socket_fd;
	args[1] = (unsigned long)NULL;
	args[2] = (unsigned long)NULL;
	int connected_socket_fd = syscall(__NR_socketcall, SYS_ACCEPT, args);
	assert_syscall_state(SYSCALL_SUCCESS, "accept (server)", connected_socket_fd, NOT_EQUAL, -1);

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
TEST(SyscallExit, socketcall_acceptX_UNIX)
{
#ifdef __s390x__
	auto evt_test = get_syscall_event_test(__NR_accept4, EXIT_EVENT);
	if(evt_test->is_kmod_engine())
		GTEST_SKIP() << "[acceptX] kmod socketcall implementation is event based (rather syscall) " << std::endl;
#else
	auto evt_test = get_syscall_event_test(__NR_accept, EXIT_EVENT);
#endif

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_socket_fd = 0;
	int32_t server_socket_fd = 0;
	struct sockaddr_un client_addr = {0};
	struct sockaddr_un server_addr = {0};
	evt_test->connect_unix_client_to_server(&client_socket_fd, &client_addr, &server_socket_fd, &server_addr);

	/* We don't want to get any info about the connected socket so `addr` and `addrlen` are NULL. */
	unsigned long args[3] = {0};
	args[0] = server_socket_fd;
	args[1] = (unsigned long)NULL;
	args[2] = (unsigned long)NULL;
	int connected_socket_fd = syscall(__NR_socketcall, SYS_ACCEPT, args);
	assert_syscall_state(SYSCALL_SUCCESS, "accept (server)", connected_socket_fd, NOT_EQUAL, -1);

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

TEST(SyscallExit, socketcall_acceptX_failure)
{
#ifdef __s390x__
	auto evt_test = get_syscall_event_test(__NR_accept4, EXIT_EVENT);
	if(evt_test->is_kmod_engine())
		GTEST_SKIP() << "[acceptX] kmod socketcall implementation is event based (rather syscall) " << std::endl;
#else
	auto evt_test = get_syscall_event_test(__NR_accept, EXIT_EVENT);
#endif

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int mock_fd = -1;
	struct sockaddr *addr = NULL;
	socklen_t *addrlen = NULL;

	unsigned long args[3] = {0};
	args[0] = mock_fd;
	args[1] = (unsigned long)addr;
	args[2] = (unsigned long)addrlen;
	assert_syscall_state(SYSCALL_FAILURE, "accept", syscall(__NR_socketcall, SYS_ACCEPT, args));
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
#endif /* __NR_accept || __s390x__ */

#if defined(__NR_accept4) && defined(__NR_connect) && defined(__NR_socket) && defined(__NR_bind) && defined(__NR_listen) && defined(__NR_close) && defined(__NR_setsockopt) && defined(__NR_shutdown)

TEST(SyscallExit, socketcall_accept4X_INET)
{
	auto evt_test = get_syscall_event_test(__NR_accept4, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_socket_fd = 0;
	int32_t server_socket_fd = 0;
	struct sockaddr_in client_addr = {0};
	struct sockaddr_in server_addr = {0};
	evt_test->connect_ipv4_client_to_server(&client_socket_fd, &client_addr, &server_socket_fd, &server_addr);

	/* We don't want to get any info about the connected socket so `addr` and `addrlen` are NULL. */
	struct sockaddr *addr = NULL;
	socklen_t *addrlen = NULL;
	int flags = 0;

	unsigned long args[4] = {0};
	args[0] = server_socket_fd;
	args[1] = (unsigned long)addr;
	args[2] = (unsigned long)addrlen;
	args[3] = flags;
	int connected_socket_fd = syscall(__NR_socketcall, SYS_ACCEPT4, args);
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

TEST(SyscallExit, socketcall_accept4X_INET6)
{
	auto evt_test = get_syscall_event_test(__NR_accept4, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_socket_fd = 0;
	int32_t server_socket_fd = 0;
	struct sockaddr_in6 client_addr = {0};
	struct sockaddr_in6 server_addr = {0};
	evt_test->connect_ipv6_client_to_server(&client_socket_fd, &client_addr, &server_socket_fd, &server_addr);

	/* We don't want to get any info about the connected socket so `addr` and `addrlen` are NULL. */
	struct sockaddr *addr = NULL;
	socklen_t *addrlen = NULL;
	int flags = 0;

	unsigned long args[4] = {0};
	args[0] = server_socket_fd;
	args[1] = (unsigned long)addr;
	args[2] = (unsigned long)addrlen;
	args[3] = flags;
	int connected_socket_fd = syscall(__NR_socketcall, SYS_ACCEPT4, args);
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
TEST(SyscallExit, socketcall_accept4X_UNIX)
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
	struct sockaddr *addr = NULL;
	socklen_t *addrlen = NULL;
	int flags = 0;

	unsigned long args[4] = {0};
	args[0] = server_socket_fd;
	args[1] = (unsigned long)addr;
	args[2] = (unsigned long)addrlen;
	args[3] = flags;
	int connected_socket_fd = syscall(__NR_socketcall, SYS_ACCEPT4, args);
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

TEST(SyscallExit, socketcall_accept4X_failure)
{
	auto evt_test = get_syscall_event_test(__NR_accept4, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t mock_fd = -1;
	struct sockaddr *addr = NULL;
	socklen_t *addrlen = NULL;
	int flags = 0;

	unsigned long args[4] = {0};
	args[0] = mock_fd;
	args[1] = (unsigned long)addr;
	args[2] = (unsigned long)addrlen;
	args[3] = flags;
	assert_syscall_state(SYSCALL_FAILURE, "accept4", syscall(__NR_socketcall, SYS_ACCEPT4, args));
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

#ifdef __NR_listen
TEST(SyscallExit, socketcall_listenX)
{
	auto evt_test = get_syscall_event_test(__NR_listen, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t socket_fd = 2;
	int backlog = 3;

	unsigned long args[2] = {0};
	args[0] = socket_fd;
	args[1] = backlog;
	assert_syscall_state(SYSCALL_FAILURE, "listen", syscall(__NR_socketcall, SYS_LISTEN, args));
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

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif

#ifdef __NR_recvfrom

#if defined(__NR_accept4) && defined(__NR_connect) && defined(__NR_socket) && defined(__NR_bind) && defined(__NR_listen) && defined(__NR_close) && defined(__NR_setsockopt) && defined(__NR_shutdown) && defined(__NR_sendto)

TEST(SyscallExit, socketcall_recvfromX_no_snaplen)
{
	auto evt_test = get_syscall_event_test(__NR_recvfrom, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_socket_fd = 0;
	int32_t server_socket_fd = 0;
	struct sockaddr_in client_addr = {0};
	struct sockaddr_in server_addr = {0};
	evt_test->connect_ipv4_client_to_server(&client_socket_fd, &client_addr, &server_socket_fd, &server_addr);

	/* Send a message to the server */
	char sent_data[NO_SNAPLEN_MESSAGE_LEN] = NO_SNAPLEN_MESSAGE;
	uint32_t sendto_flags = 0;
	int64_t sent_bytes = syscall(__NR_sendto, client_socket_fd, sent_data, sizeof(sent_data), sendto_flags, (struct sockaddr *)&server_addr, sizeof(server_addr));
	assert_syscall_state(SYSCALL_SUCCESS, "sendto (client)", sent_bytes, NOT_EQUAL, -1);

	/* The server accepts the connection and receives the message */
	int connected_socket_fd = syscall(__NR_accept4, server_socket_fd, NULL, NULL, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "accept4 (server)", connected_socket_fd, NOT_EQUAL, -1);

	char received_data[MAX_RECV_BUF_SIZE];
	socklen_t received_data_len = MAX_RECV_BUF_SIZE;
	uint32_t recvfrom_flags = 0;
	/// TODO: if we use `struct sockaddr_in* src_addr = NULL` kernel module and old bpf are not able to get correct data.
	/// Fixing them means changing how we retrieve network data, so it would be quite a big change.
	struct sockaddr_in src_addr = {0};
	socklen_t addrlen = sizeof(src_addr);

	unsigned long args[6] = {0};
	args[0] = connected_socket_fd;
	args[1] = (unsigned long)received_data;
	args[2] = received_data_len;
	args[3] = recvfrom_flags;
	args[4] = (unsigned long)&src_addr;
	args[5] = (unsigned long)&addrlen;

	int64_t received_bytes = syscall(__NR_socketcall, SYS_RECVFROM, args);
	assert_syscall_state(SYSCALL_SUCCESS, "recvfrom (server)", received_bytes, NOT_EQUAL, -1);

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

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)received_bytes);

	/* Parameter 2: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(2, NO_SNAPLEN_MESSAGE, received_bytes);

	/* Parameter 3: tuple (type: PT_SOCKTUPLE) */
	/* The server performs a 'recvfrom` so the server is the final destination of the packet while the client is the src. */
	evt_test->assert_tuple_inet_param(3, PPM_AF_INET, IPV4_CLIENT, IPV4_SERVER, IPV4_PORT_CLIENT_STRING, IPV4_PORT_SERVER_STRING);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}

TEST(SyscallExit, socketcall_recvfromX_snaplen)
{
	auto evt_test = get_syscall_event_test(__NR_recvfrom, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_socket_fd = 0;
	int32_t server_socket_fd = 0;
	struct sockaddr_in client_addr = {0};
	struct sockaddr_in server_addr = {0};
	evt_test->connect_ipv4_client_to_server(&client_socket_fd, &client_addr, &server_socket_fd, &server_addr);

	/* Send a message to the server */
	char sent_data[FULL_MESSAGE_LEN] = FULL_MESSAGE;
	uint32_t sendto_flags = 0;
	int64_t sent_bytes = syscall(__NR_sendto, client_socket_fd, sent_data, sizeof(sent_data), sendto_flags, (struct sockaddr *)&server_addr, sizeof(server_addr));
	assert_syscall_state(SYSCALL_SUCCESS, "sendto (client)", sent_bytes, NOT_EQUAL, -1);

	/* The server accepts the connection and receives the message */
	int connected_socket_fd = syscall(__NR_accept4, server_socket_fd, NULL, NULL, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "accept4 (server)", connected_socket_fd, NOT_EQUAL, -1);

	char received_data[MAX_RECV_BUF_SIZE];
	socklen_t received_data_len = MAX_RECV_BUF_SIZE;
	uint32_t recvfrom_flags = 0;
	struct sockaddr_in src_addr = {0};
	socklen_t addrlen = sizeof(src_addr);

	unsigned long args[6] = {0};
	args[0] = connected_socket_fd;
	args[1] = (unsigned long)received_data;
	args[2] = received_data_len;
	args[3] = recvfrom_flags;
	args[4] = (unsigned long)&src_addr;
	args[5] = (unsigned long)&addrlen;

	int64_t received_bytes = syscall(__NR_socketcall, SYS_RECVFROM, args);
	assert_syscall_state(SYSCALL_SUCCESS, "recvfrom (server)", received_bytes, NOT_EQUAL, -1);

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

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)MAX_RECV_BUF_SIZE);

	/* Parameter 2: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(2, FULL_MESSAGE, DEFAULT_SNAPLEN);

	/* Parameter 3: tuple (type: PT_SOCKTUPLE) */
	/* The server performs a 'recvfrom` so the server is the final destination of the packet while the client is the src. */
	evt_test->assert_tuple_inet_param(3, PPM_AF_INET, IPV4_CLIENT, IPV4_SERVER, IPV4_PORT_CLIENT_STRING, IPV4_PORT_SERVER_STRING);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}
#endif

TEST(SyscallExit, socketcall_recvfromX_fail)
{
	auto evt_test = get_syscall_event_test(__NR_recvfrom, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t mock_fd = -1;
	char received_data[MAX_RECV_BUF_SIZE];
	socklen_t received_data_len = MAX_RECV_BUF_SIZE;
	uint32_t flags = 0;
	struct sockaddr *src_addr = NULL;
	socklen_t *addrlen = NULL;

	unsigned long args[6] = {0};
	args[0] = mock_fd;
	args[1] = (unsigned long)received_data;
	args[2] = received_data_len;
	args[3] = flags;
	args[4] = (unsigned long)src_addr;
	args[5] = (unsigned long)addrlen;

	assert_syscall_state(SYSCALL_FAILURE, "recvfrom", syscall(__NR_socketcall, SYS_RECVFROM, args));
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

	/* Parameter 2: data (type: PT_BYTEBUF) */
	evt_test->assert_empty_param(2);

	/* Parameter 3: tuple (type: PT_SOCKTUPLE) */
	evt_test->assert_empty_param(3);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}

#endif

#if defined(__NR_socketpair) && defined(__NR_close)

#include <sys/socket.h>

TEST(SyscallExit, socketcall_socketpairX_success)
{
	auto evt_test = get_syscall_event_test(__NR_socketpair, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int domain = PF_LOCAL;
	int type = SOCK_STREAM;
	int protocol = 0;
	int32_t fd[2];

	unsigned long args[4] = {0};
	args[0] = domain;
	args[1] = type;
	args[2] = protocol;
	args[3] = (unsigned long)fd;
	assert_syscall_state(SYSCALL_SUCCESS, "socketpair", syscall(__NR_socketcall, SYS_SOCKETPAIR, args), NOT_EQUAL, -1);
	syscall(__NR_close, fd[0]);
	syscall(__NR_close, fd[1]);

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
	evt_test->assert_numeric_param(1, (int64_t)0);

	/* Parameter 2: fd1 (type: PT_FD)*/
	evt_test->assert_numeric_param(2, (int64_t)fd[0]);

	/* Parameter 3: fd2 (type: PT_FD)*/
	evt_test->assert_numeric_param(3, (int64_t)fd[1]);

	/* Parameter 4: source (type: PT_UINT64)*/
	/* Here we have a kernel pointer, we don't know the exact value. */
	evt_test->assert_numeric_param(4, (uint64_t)0, NOT_EQUAL);

	/* Parameter 5: peer (type: PT_UINT64)*/
	/* Here we have a kernel pointer, we don't know the exact value. */
	evt_test->assert_numeric_param(5, (uint64_t)0, NOT_EQUAL);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

TEST(SyscallExit, socketcall_socketpairX_failure)
{
	auto evt_test = get_syscall_event_test(__NR_socketpair, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int domain = PF_LOCAL;
	int type = SOCK_STREAM;
	int protocol = 0;
	int32_t* fd = NULL;

	unsigned long args[4] = {0};
	args[0] = domain;
	args[1] = type;
	args[2] = protocol;
	args[3] = (unsigned long)fd;
	assert_syscall_state(SYSCALL_SUCCESS, "socketpair", syscall(__NR_socketcall, SYS_SOCKETPAIR, args));
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

	/* Parameter 2: fd1 (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)-1);

	/* Parameter 3: fd2 (type: PT_FD) */
	evt_test->assert_numeric_param(3, (int64_t)-1);

	/* Parameter 4: source (type: PT_UINT64) */
	evt_test->assert_numeric_param(4, (uint64_t)0);

	/* Parameter 5: peer (type: PT_UINT64) */
	evt_test->assert_numeric_param(5, (uint64_t)0);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

#endif

#ifdef __NR_sendto

#if defined(__NR_connect) && defined(__NR_socket) && defined(__NR_bind) && defined(__NR_listen) && defined(__NR_close) && defined(__NR_setsockopt) && defined(__NR_shutdown)

/* By default `snaplen` is 80 bytes.
 * No `snaplen` because here we don't hit the 80 bytes so we don't have to truncate the message.
 */
TEST(SyscallExit, socketcall_sendtoX_no_snaplen)
{
	auto evt_test = get_syscall_event_test(__NR_sendto, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_socket_fd = 0;
	int32_t server_socket_fd = 0;
	struct sockaddr_in client_addr = {0};
	struct sockaddr_in server_addr = {0};
	evt_test->connect_ipv4_client_to_server(&client_socket_fd, &client_addr, &server_socket_fd, &server_addr);

	/* Send a message to the server */
	char sent_data[NO_SNAPLEN_MESSAGE_LEN] = NO_SNAPLEN_MESSAGE;
	uint32_t sendto_flags = 0;

	unsigned long args[6] = {0};
	args[0] = client_socket_fd;
	args[1] = (unsigned long)sent_data;
	args[2] = sizeof(sent_data);
	args[3] = sendto_flags;
	args[4] = (unsigned long)&server_addr;
	args[5] = sizeof(server_addr);
	int64_t sent_bytes = syscall(__NR_socketcall, SYS_SENDTO, args);
	assert_syscall_state(SYSCALL_SUCCESS, "sendto (client)", sent_bytes, NOT_EQUAL, -1);

	/* Cleaning phase */
	syscall(__NR_shutdown, server_socket_fd, 2);
	syscall(__NR_shutdown, client_socket_fd, 2);
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

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)sent_bytes);

	/* Parameter 2: data (type: PT_BYTEBUF)*/
	evt_test->assert_bytebuf_param(2, NO_SNAPLEN_MESSAGE, sent_bytes);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

/* Here we need to truncate our message since it is greater than `snaplen` */
TEST(SyscallExit, socketcall_sendtoX_snaplen)
{
	auto evt_test = get_syscall_event_test(__NR_sendto, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_socket_fd = 0;
	int32_t server_socket_fd = 0;
	struct sockaddr_in client_addr = {0};
	struct sockaddr_in server_addr = {0};
	evt_test->connect_ipv4_client_to_server(&client_socket_fd, &client_addr, &server_socket_fd, &server_addr);

	/* Send a message to the server */
	char sent_data[FULL_MESSAGE_LEN] = FULL_MESSAGE;
	uint32_t sendto_flags = 0;

	unsigned long args[6] = {0};
	args[0] = client_socket_fd;
	args[1] = (unsigned long)sent_data;
	args[2] = sizeof(sent_data);
	args[3] = sendto_flags;
	args[4] = (unsigned long)&server_addr;
	args[5] = sizeof(server_addr);
	int64_t sent_bytes = syscall(__NR_socketcall, SYS_SENDTO, args);
	assert_syscall_state(SYSCALL_SUCCESS, "sendto (client)", sent_bytes, NOT_EQUAL, -1);

	/* Cleaning phase */
	syscall(__NR_shutdown, server_socket_fd, 2);
	syscall(__NR_shutdown, client_socket_fd, 2);
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

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)sent_bytes);

	/* Parameter 2: data (type: PT_BYTEBUF)*/
	evt_test->assert_bytebuf_param(2, FULL_MESSAGE, DEFAULT_SNAPLEN);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}
#endif

TEST(SyscallExit, socketcall_sendtoX_fail)
{
	auto evt_test = get_syscall_event_test(__NR_sendto, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t mock_fd = -1;
	char* sent_data = NULL;
	size_t len = 0;
	uint32_t sendto_flags = 0;
	struct sockaddr* dest_addr = NULL;
	socklen_t addrlen = 0;

	unsigned long args[6] = {0};
	args[0] = mock_fd;
	args[1] = (unsigned long)sent_data;
	args[2] = len;
	args[3] = sendto_flags;
	args[4] = (unsigned long)dest_addr;
	args[5] = addrlen;
	assert_syscall_state(SYSCALL_FAILURE, "sendto", syscall(__NR_socketcall, SYS_SENDTO, args));
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

	/* Parameter 2: data (type: PT_BYTEBUF)*/
	evt_test->assert_empty_param(2);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

#endif /* __NR_sendto */

#ifdef __NR_sendmsg

#if defined(__NR_connect) && defined(__NR_socket) && defined(__NR_bind) && defined(__NR_listen) && defined(__NR_close) && defined(__NR_setsockopt) && defined(__NR_shutdown)

/* By default `snaplen` is 80 bytes.
 * No `snaplen` because here we don't hit the 80 bytes so we don't have to truncate the message.
 */
TEST(SyscallExit, socketcall_sendmsgX_no_snaplen)
{
	auto evt_test = get_syscall_event_test(__NR_sendmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_socket_fd = 0;
	int32_t server_socket_fd = 0;
	struct sockaddr_in client_addr = {0};
	struct sockaddr_in server_addr = {0};
	evt_test->connect_ipv4_client_to_server(&client_socket_fd, &client_addr, &server_socket_fd, &server_addr);

	/* Send a message to the server */
	struct msghdr send_msg;
	struct iovec iov[2];
	memset(&send_msg, 0, sizeof(send_msg));
	memset(iov, 0, sizeof(iov));
	send_msg.msg_name = (struct sockaddr*)&server_addr;
	send_msg.msg_namelen = sizeof(server_addr);
	char sent_data_1[FIRST_MESSAGE_LEN] = "hey! there is a first message here.";
	char sent_data_2[SECOND_MESSAGE_LEN] = "hey! there is a second message here.";
	iov[0].iov_base = sent_data_1;
	iov[0].iov_len = sizeof(sent_data_1);
	iov[1].iov_base = sent_data_2;
	iov[1].iov_len = sizeof(sent_data_2);
	send_msg.msg_iov = iov;
	send_msg.msg_iovlen = 2;
	uint32_t sendmsg_flags = 0;

	unsigned long args[3] = {0};
	args[0] = client_socket_fd;
	args[1] = (unsigned long)&send_msg;
	args[2] = sendmsg_flags;
	int64_t sent_bytes = syscall(__NR_socketcall, SYS_SENDMSG, args);
	assert_syscall_state(SYSCALL_SUCCESS, "sendmsg (client)", sent_bytes, NOT_EQUAL, -1);

	/* Cleaning phase */
	syscall(__NR_shutdown, server_socket_fd, 2);
	syscall(__NR_shutdown, client_socket_fd, 2);
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

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)sent_bytes);

	/* Parameter 2: data (type: PT_BYTEBUF)*/
	evt_test->assert_bytebuf_param(2, NO_SNAPLEN_MESSAGE, sent_bytes);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

/* Here we need to truncate our message since it is greater than `snaplen` */
TEST(SyscallExit, socketcall_sendmsgX_snaplen)
{
	auto evt_test = get_syscall_event_test(__NR_sendmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_socket_fd = 0;
	int32_t server_socket_fd = 0;
	struct sockaddr_in client_addr = {0};
	struct sockaddr_in server_addr = {0};
	evt_test->connect_ipv4_client_to_server(&client_socket_fd, &client_addr, &server_socket_fd, &server_addr);

	/* Send a message to the server */
	struct msghdr send_msg;
	struct iovec iov[3];
	memset(&send_msg, 0, sizeof(send_msg));
	memset(iov, 0, sizeof(iov));
	send_msg.msg_name = (struct sockaddr*)&server_addr;
	send_msg.msg_namelen = sizeof(server_addr);
	char sent_data_1[FIRST_MESSAGE_LEN] = "hey! there is a first message here.";
	char sent_data_2[SECOND_MESSAGE_LEN] = "hey! there is a second message here.";
	char sent_data_3[THIRD_MESSAGE_LEN] = "hey! there is a third message here.";
	iov[0].iov_base = sent_data_1;
	iov[0].iov_len = sizeof(sent_data_1);
	iov[1].iov_base = sent_data_2;
	iov[1].iov_len = sizeof(sent_data_2);
	iov[2].iov_base = sent_data_3;
	iov[2].iov_len = sizeof(sent_data_3);
	send_msg.msg_iov = iov;
	send_msg.msg_iovlen = 3;
	uint32_t sendmsg_flags = 0;

	unsigned long args[3] = {0};
	args[0] = client_socket_fd;
	args[1] = (unsigned long)&send_msg;
	args[2] = sendmsg_flags;
	int64_t sent_bytes = syscall(__NR_socketcall, SYS_SENDMSG, args);
	assert_syscall_state(SYSCALL_SUCCESS, "sendmsg (client)", sent_bytes, NOT_EQUAL, -1);

	/* Cleaning phase */
	syscall(__NR_shutdown, server_socket_fd, 2);
	syscall(__NR_shutdown, client_socket_fd, 2);
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

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)sent_bytes);

	/* Parameter 2: data (type: PT_BYTEBUF)*/
	evt_test->assert_bytebuf_param(2, FULL_MESSAGE, DEFAULT_SNAPLEN);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}
#endif

TEST(SyscallExit, socketcall_sendmsgX_fail)
{
	auto evt_test = get_syscall_event_test(__NR_sendmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t mock_fd = -1;
	struct msghdr* send_msg = NULL;
	uint32_t sendmsg_flags = 0;

	unsigned long args[3] = {0};
	args[0] = mock_fd;
	args[1] = (unsigned long)&send_msg;
	args[2] = sendmsg_flags;
	assert_syscall_state(SYSCALL_FAILURE, "sendmsg", syscall(__NR_socketcall, SYS_SENDMSG, args));
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

	/* Parameter 2: data (type: PT_BYTEBUF)*/
	evt_test->assert_empty_param(2);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

#endif /* __NR_sendmsg */

#ifdef __NR_recvmsg

#if defined(__NR_accept4) && defined(__NR_connect) && defined(__NR_socket) && defined(__NR_bind) && defined(__NR_listen) && defined(__NR_close) && defined(__NR_setsockopt) && defined(__NR_shutdown) && defined(__NR_sendto)

TEST(SyscallExit, socketcall_recvmsgX_no_snaplen)
{
	auto evt_test = get_syscall_event_test(__NR_recvmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_socket_fd = 0;
	int32_t server_socket_fd = 0;
	struct sockaddr_in client_addr = {0};
	struct sockaddr_in server_addr = {0};
	evt_test->connect_ipv4_client_to_server(&client_socket_fd, &client_addr, &server_socket_fd, &server_addr);

	/* Send a message to the server */
	char sent_data[NO_SNAPLEN_MESSAGE_LEN] = NO_SNAPLEN_MESSAGE;
	uint32_t sendto_flags = 0;
	int64_t sent_bytes = syscall(__NR_sendto, client_socket_fd, sent_data, sizeof(sent_data), sendto_flags, (struct sockaddr *)&server_addr, sizeof(server_addr));
	assert_syscall_state(SYSCALL_SUCCESS, "sendto (client)", sent_bytes, NOT_EQUAL, -1);

	/* The server accepts the connection and receives the message */
	int connected_socket_fd = syscall(__NR_accept4, server_socket_fd, NULL, NULL, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "accept4 (server)", connected_socket_fd, NOT_EQUAL, -1);

	struct msghdr recv_msg;
	struct iovec iov[2];
	memset(&recv_msg, 0, sizeof(recv_msg));
	memset(iov, 0, sizeof(iov));
	recv_msg.msg_name = (struct sockaddr *)&client_addr;
	recv_msg.msg_namelen = sizeof(client_addr);
	char data_1[MAX_RECV_BUF_SIZE];
	char data_2[MAX_RECV_BUF_SIZE];
	iov[0].iov_base = data_1;
	iov[0].iov_len = MAX_RECV_BUF_SIZE;
	iov[1].iov_base = data_2;
	iov[1].iov_len = MAX_RECV_BUF_SIZE;
	recv_msg.msg_iov = iov;
	recv_msg.msg_iovlen = 2;
	uint32_t recvmsg_flags = 0;

	unsigned long args[3] = {0};
	args[0] = connected_socket_fd;
	args[1] = (unsigned long)&recv_msg;
	args[2] = recvmsg_flags;
	int64_t received_bytes = syscall(__NR_socketcall, SYS_RECVMSG, args);
	assert_syscall_state(SYSCALL_SUCCESS, "recvmsg (server)", received_bytes, NOT_EQUAL, -1);

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

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)received_bytes);

	/* Parameter 2: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (uint32_t)received_bytes);

	/* Parameter 3: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(3, NO_SNAPLEN_MESSAGE, sent_bytes);

	/* Parameter 4: tuple (type: PT_SOCKTUPLE) */

	if(evt_test->is_modern_bpf_engine())
	{
		/* The server performs a 'recvmsg` so the server is the final destination of the packet while the client is the src. */
		evt_test->assert_tuple_inet_param(4, PPM_AF_INET, IPV4_CLIENT, IPV4_SERVER, IPV4_PORT_CLIENT_STRING, IPV4_PORT_SERVER_STRING);
	}
	else
	{
		/// TODO: same as `recvfrom` the kernel code tries to get information from userspace structs
		///  but these could be empty so this is not the correct way to retrieve information we have to
		///  change it.
		evt_test->assert_empty_param(4);
		evt_test->assert_num_params_pushed(4);
		GTEST_SKIP() << "[RECVMSG_X]: what we receive is correct but we need to reimplement it, see the code" << std::endl;
	}

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);
}

TEST(SyscallExit, socketcall_recvmsgX_snaplen)
{
	auto evt_test = get_syscall_event_test(__NR_recvmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_socket_fd = 0;
	int32_t server_socket_fd = 0;
	struct sockaddr_in client_addr = {0};
	struct sockaddr_in server_addr = {0};
	evt_test->connect_ipv4_client_to_server(&client_socket_fd, &client_addr, &server_socket_fd, &server_addr);

	/* Send a message to the server */
	char sent_data[FULL_MESSAGE_LEN] = FULL_MESSAGE;
	uint32_t sendto_flags = 0;
	int64_t sent_bytes = syscall(__NR_sendto, client_socket_fd, sent_data, sizeof(sent_data), sendto_flags, (struct sockaddr *)&server_addr, sizeof(server_addr));
	assert_syscall_state(SYSCALL_SUCCESS, "sendto (client)", sent_bytes, NOT_EQUAL, -1);

	/* The server accepts the connection and receives the message */
	int connected_socket_fd = syscall(__NR_accept4, server_socket_fd, NULL, NULL, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "accept4 (server)", connected_socket_fd, NOT_EQUAL, -1);

	struct msghdr recv_msg;
	struct iovec iov[2];
	memset(&recv_msg, 0, sizeof(recv_msg));
	memset(iov, 0, sizeof(iov));
	recv_msg.msg_name = (struct sockaddr *)&client_addr;
	recv_msg.msg_namelen = sizeof(client_addr);
	char data_1[MAX_RECV_BUF_SIZE];
	char data_2[MAX_RECV_BUF_SIZE];
	iov[0].iov_base = data_1;
	iov[0].iov_len = MAX_RECV_BUF_SIZE;
	iov[1].iov_base = data_2;
	iov[1].iov_len = MAX_RECV_BUF_SIZE;
	recv_msg.msg_iov = iov;
	recv_msg.msg_iovlen = 2;
	uint32_t recvmsg_flags = 0;

	unsigned long args[3] = {0};
	args[0] = connected_socket_fd;
	args[1] = (unsigned long)&recv_msg;
	args[2] = recvmsg_flags;
	int64_t received_bytes = syscall(__NR_socketcall, SYS_RECVMSG, args);
	assert_syscall_state(SYSCALL_SUCCESS, "recvmsg (server)", received_bytes, NOT_EQUAL, -1);

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

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)FULL_MESSAGE_LEN);

	/* Parameter 2: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (uint32_t)FULL_MESSAGE_LEN);

	/* Parameter 3: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(3, FULL_MESSAGE, DEFAULT_SNAPLEN);

	if(evt_test->is_modern_bpf_engine())
	{
		/* Parameter 4: tuple (type: PT_SOCKTUPLE) */
		/* The server performs a 'recvmsg` so the server is the final destination of the packet while the client is the src. */
		evt_test->assert_tuple_inet_param(4, PPM_AF_INET, IPV4_CLIENT, IPV4_SERVER, IPV4_PORT_CLIENT_STRING, IPV4_PORT_SERVER_STRING);
	}
	else
	{
		/// TODO: same as `recvfrom` the kernel code tries to get information from userspace structs
		///  but these could be empty so this is not the correct way to retrieve information we have to
		///  change it.
		evt_test->assert_empty_param(4);
		evt_test->assert_num_params_pushed(4);
		GTEST_SKIP() << "[RECVMSG_X]: what we receive is correct but we need to reimplement it, see the code" << std::endl;
	}

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);
}
#endif

TEST(SyscallExit, socketcall_recvmsgX_fail)
{
	auto evt_test = get_syscall_event_test(__NR_recvmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t mock_fd = -1;
	struct msghdr *msg = NULL;
	int flags = 0;

	unsigned long args[3] = {0};
	args[0] = mock_fd;
	args[1] = (unsigned long)msg;
	args[2] = flags;
	assert_syscall_state(SYSCALL_FAILURE, "recvmsg", syscall(__NR_socketcall, SYS_RECVMSG, args));
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

	/* Parameter 2: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (uint32_t)0);

	/* Parameter 3: data (type: PT_BYTEBUF) */
	evt_test->assert_empty_param(3);

	/* Parameter 4: tuple (type: PT_SOCKTUPLE) */
	evt_test->assert_empty_param(4);

	/*=============================== ASSERT PARAMETERS  ===========================*/
}

#endif

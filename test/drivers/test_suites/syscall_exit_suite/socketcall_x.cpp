#include "../../event_class/event_class.h"

#ifdef __NR_socketcall

#if defined(__NR_socket) && defined(__NR_bind) && defined(__NR_connect)

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
	clone_args cl_args = {0};
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

	sockaddr_in server_addr;
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

	sockaddr_in client_addr;
	evt_test->client_fill_sockaddr_in(&client_addr);

	/* We need to bind the client socket with an address otherwise we cannot assert against it. */
	assert_syscall_state(SYSCALL_SUCCESS, "bind (client)", syscall(__NR_bind, client_socket_fd, (sockaddr*)&client_addr, sizeof(client_addr)), NOT_EQUAL, -1);

	/* Now we associate the client socket with the server address. */
	sockaddr_in server_addr;
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

	/* Parameter 3: fd (type: PT_FD) */
	evt_test->assert_numeric_param(3, (int64_t)client_socket_fd);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
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
	/* The kmod/bpf can correctly handle accept also on s390x */
	if(evt_test->is_kmod_engine() || evt_test->is_bpf_engine())
	{
		/* we cannot set `__NR_accept` explicitly since it is not defined on s390x
		 * we activate all syscalls.
		 */
		evt_test.reset(get_syscall_event_test().release());
		evt_test->set_event_type(PPME_SOCKET_ACCEPT_5_X);
	}
#else
	auto evt_test = get_syscall_event_test(__NR_accept, EXIT_EVENT);
#endif

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_socket_fd = 0;
	int32_t server_socket_fd = 0;
	sockaddr_in client_addr = {0};
	sockaddr_in server_addr = {0};
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
	/* The kmod/bpf can correctly handle accept also on s390x */
	if(evt_test->is_kmod_engine() || evt_test->is_bpf_engine())
	{
		/* we cannot set `__NR_accept` explicitly since it is not defined on s390x
		 * we activate all syscalls.
		 */
		evt_test.reset(get_syscall_event_test().release());
		evt_test->set_event_type(PPME_SOCKET_ACCEPT_5_X);
	}
#else
	auto evt_test = get_syscall_event_test(__NR_accept, EXIT_EVENT);
#endif

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_socket_fd = 0;
	int32_t server_socket_fd = 0;
	sockaddr_in6 client_addr = {0};
	sockaddr_in6 server_addr = {0};
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
	/* The kmod/bpf can correctly handle accept also on s390x */
	if(evt_test->is_kmod_engine() || evt_test->is_bpf_engine())
	{
		/* we cannot set `__NR_accept` explicitly since it is not defined on s390x
		 * we activate all syscalls.
		 */
		evt_test.reset(get_syscall_event_test().release());
		evt_test->set_event_type(PPME_SOCKET_ACCEPT_5_X);
	}
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
	/* The kmod/bpf can correctly handle accept also on s390x */
	if(evt_test->is_kmod_engine() || evt_test->is_bpf_engine())
	{
		/* we cannot set `__NR_accept` explicitly since it is not defined on s390x
		 * we activate all syscalls.
		 */
		evt_test.reset(get_syscall_event_test().release());
		evt_test->set_event_type(PPME_SOCKET_ACCEPT_5_X);
	}
#else
	auto evt_test = get_syscall_event_test(__NR_accept, EXIT_EVENT);
#endif

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int mock_fd = -1;
	sockaddr* addr = NULL;
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
	sockaddr_in client_addr = {0};
	sockaddr_in server_addr = {0};
	evt_test->connect_ipv4_client_to_server(&client_socket_fd, &client_addr, &server_socket_fd, &server_addr);

	/* We don't want to get any info about the connected socket so `addr` and `addrlen` are NULL. */
	sockaddr* addr = NULL;
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
	sockaddr_in6 client_addr = {0};
	sockaddr_in6 server_addr = {0};
	evt_test->connect_ipv6_client_to_server(&client_socket_fd, &client_addr, &server_socket_fd, &server_addr);

	/* We don't want to get any info about the connected socket so `addr` and `addrlen` are NULL. */
	sockaddr* addr = NULL;
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
	sockaddr* addr = NULL;
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
	sockaddr* addr = NULL;
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
	sockaddr_in client_addr = {0};
	sockaddr_in server_addr = {0};
	evt_test->connect_ipv4_client_to_server(&client_socket_fd, &client_addr, &server_socket_fd, &server_addr);

	/* Send a message to the server */
	char sent_data[NO_SNAPLEN_MESSAGE_LEN] = NO_SNAPLEN_MESSAGE;
	uint32_t sendto_flags = 0;
	int64_t sent_bytes = syscall(__NR_sendto, client_socket_fd, sent_data, sizeof(sent_data), sendto_flags, (sockaddr*)&server_addr, sizeof(server_addr));
	assert_syscall_state(SYSCALL_SUCCESS, "sendto (client)", sent_bytes, NOT_EQUAL, -1);

	/* The server accepts the connection and receives the message */
	int connected_socket_fd = syscall(__NR_accept4, server_socket_fd, NULL, NULL, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "accept4 (server)", connected_socket_fd, NOT_EQUAL, -1);

	char received_data[MAX_RECV_BUF_SIZE];
	socklen_t received_data_len = MAX_RECV_BUF_SIZE;
	uint32_t recvfrom_flags = 0;
	/// TODO: if we use `sockaddr_in* src_addr = NULL` kernel module and old bpf are not able to get correct data.
	/// Fixing them means changing how we retrieve network data, so it would be quite a big change.
	sockaddr_in src_addr = {0};
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
	sockaddr_in client_addr = {0};
	sockaddr_in server_addr = {0};
	evt_test->connect_ipv4_client_to_server(&client_socket_fd, &client_addr, &server_socket_fd, &server_addr);

	/* Send a message to the server */
	char sent_data[FULL_MESSAGE_LEN] = FULL_MESSAGE;
	uint32_t sendto_flags = 0;
	int64_t sent_bytes = syscall(__NR_sendto, client_socket_fd, sent_data, sizeof(sent_data), sendto_flags, (sockaddr*)&server_addr, sizeof(server_addr));
	assert_syscall_state(SYSCALL_SUCCESS, "sendto (client)", sent_bytes, NOT_EQUAL, -1);

	/* The server accepts the connection and receives the message */
	int connected_socket_fd = syscall(__NR_accept4, server_socket_fd, NULL, NULL, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "accept4 (server)", connected_socket_fd, NOT_EQUAL, -1);

	char received_data[MAX_RECV_BUF_SIZE];
	socklen_t received_data_len = MAX_RECV_BUF_SIZE;
	uint32_t recvfrom_flags = 0;
	sockaddr_in src_addr = {0};
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
	sockaddr* src_addr = NULL;
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
	int32_t *fd = NULL;

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
	sockaddr_in client_addr = {0};
	sockaddr_in server_addr = {0};
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
	sockaddr_in client_addr = {0};
	sockaddr_in server_addr = {0};
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
	char sent_data[DEFAULT_SNAPLEN / 2] = "some-data";
	size_t len = DEFAULT_SNAPLEN / 2;
	uint32_t sendto_flags = 0;
	sockaddr* dest_addr = NULL;
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
	evt_test->assert_bytebuf_param(2, sent_data, DEFAULT_SNAPLEN / 2);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

TEST(SyscallExit, socketcall_sendtoX_empty)
{
	auto evt_test = get_syscall_event_test(__NR_sendto, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t mock_fd = -1;
	char *sent_data = NULL;
	size_t len = 0;
	uint32_t sendto_flags = 0;
	sockaddr* dest_addr = NULL;
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
	sockaddr_in client_addr = {0};
	sockaddr_in server_addr = {0};
	evt_test->connect_ipv4_client_to_server(&client_socket_fd, &client_addr, &server_socket_fd, &server_addr);

	/* Send a message to the server */
	struct msghdr send_msg;
	struct iovec iov[2];
	memset(&send_msg, 0, sizeof(send_msg));
	memset(iov, 0, sizeof(iov));
	send_msg.msg_name = (sockaddr*)&server_addr;
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
	sockaddr_in client_addr = {0};
	sockaddr_in server_addr = {0};
	evt_test->connect_ipv4_client_to_server(&client_socket_fd, &client_addr, &server_socket_fd, &server_addr);

	/* Send a message to the server */
	struct msghdr send_msg;
	struct iovec iov[3];
	memset(&send_msg, 0, sizeof(send_msg));
	memset(iov, 0, sizeof(iov));
	send_msg.msg_name = (sockaddr*)&server_addr;
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
	struct msghdr send_msg = {0};
	struct iovec iov[1] = {0};
	memset(&send_msg, 0, sizeof(send_msg));
	memset(iov, 0, sizeof(iov));
	char sent_data_1[DEFAULT_SNAPLEN / 2] = "some-data";
	iov[0].iov_base = sent_data_1;
	iov[0].iov_len = sizeof(sent_data_1);
	send_msg.msg_iov = iov;
	/* here we pass a wrong `iovlen` to check the behavior */
	send_msg.msg_iovlen = 3;
	uint32_t sendmsg_flags = 0;

	unsigned long args[3] = {0};
	args[0] = mock_fd;
	args[1] = (unsigned long)&send_msg;
	args[2] = sendmsg_flags;
	assert_syscall_state(SYSCALL_FAILURE, "sendmsg", syscall(__NR_socketcall, SYS_SENDMSG, args));
	int64_t errno_value = -errno;

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	if(evt_test->is_modern_bpf_engine())
	{
		evt_test->assert_event_presence();
	}
	else
	{
		/* we need to rewrite the logic in old drivers to support this partial collection
		 * right now we drop the entire event.
		 */
		evt_test->assert_event_absence();
		GTEST_SKIP() << "[SENDMSG_X]: what we receive is correct but we need to reimplement it, see the code" << std::endl;
	}

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
	evt_test->assert_bytebuf_param(2, sent_data_1, DEFAULT_SNAPLEN / 2);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

TEST(SyscallExit, socketcall_sendmsgX_null_iovec)
{
	auto evt_test = get_syscall_event_test(__NR_sendmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t mock_fd = -1;
	struct msghdr send_msg = {0};
	memset(&send_msg, 0, sizeof(send_msg));
	send_msg.msg_iov = NULL;
	/* here we pass a wrong `iovlen` to check the behavior */
	send_msg.msg_iovlen = 3;
	uint32_t sendmsg_flags = 0;

	unsigned long args[3] = {0};
	args[0] = mock_fd;
	args[1] = (unsigned long)&send_msg;
	args[2] = sendmsg_flags;
	assert_syscall_state(SYSCALL_FAILURE, "sendmsg", syscall(__NR_socketcall, SYS_SENDMSG, args));
	int64_t errno_value = -errno;

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	if(evt_test->is_modern_bpf_engine())
	{
		evt_test->assert_event_presence();
	}
	else
	{
		/* we need to rewrite the logic in old drivers to support this partial collection
		 * right now we drop the entire event.
		 */
		evt_test->assert_event_absence();
		GTEST_SKIP() << "[SENDMSG_X]: what we receive is correct but we need to reimplement it, see the code" << std::endl;
	}

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

TEST(SyscallExit, socketcall_sendmsgX_null_msghdr)
{
	auto evt_test = get_syscall_event_test(__NR_sendmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t mock_fd = -1;
	struct msghdr *send_msg = NULL;
	uint32_t sendmsg_flags = 0;

	unsigned long args[3] = {0};
	args[0] = mock_fd;
	args[1] = (unsigned long)send_msg;
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
	sockaddr_in client_addr = {0};
	sockaddr_in server_addr = {0};
	evt_test->connect_ipv4_client_to_server(&client_socket_fd, &client_addr, &server_socket_fd, &server_addr);

	/* Send a message to the server */
	char sent_data[NO_SNAPLEN_MESSAGE_LEN] = NO_SNAPLEN_MESSAGE;
	uint32_t sendto_flags = 0;
	int64_t sent_bytes = syscall(__NR_sendto, client_socket_fd, sent_data, sizeof(sent_data), sendto_flags, (sockaddr*)&server_addr, sizeof(server_addr));
	assert_syscall_state(SYSCALL_SUCCESS, "sendto (client)", sent_bytes, NOT_EQUAL, -1);

	/* The server accepts the connection and receives the message */
	int connected_socket_fd = syscall(__NR_accept4, server_socket_fd, NULL, NULL, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "accept4 (server)", connected_socket_fd, NOT_EQUAL, -1);

	struct msghdr recv_msg;
	struct iovec iov[2];
	memset(&recv_msg, 0, sizeof(recv_msg));
	memset(iov, 0, sizeof(iov));
	recv_msg.msg_name = (sockaddr*)&client_addr;
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
		evt_test->assert_num_params_pushed(5);
		GTEST_SKIP() << "[RECVMSG_X]: what we receive is correct but we need to reimplement it, see the code" << std::endl;
	}

	/* Parameter 5: msg_control (type: PT_BYTEBUF) */
	evt_test->assert_empty_param(5);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

TEST(SyscallExit, socketcall_recvmsgX_snaplen)
{
	auto evt_test = get_syscall_event_test(__NR_recvmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_socket_fd = 0;
	int32_t server_socket_fd = 0;
	sockaddr_in client_addr = {0};
	sockaddr_in server_addr = {0};
	evt_test->connect_ipv4_client_to_server(&client_socket_fd, &client_addr, &server_socket_fd, &server_addr);

	/* Send a message to the server */
	char sent_data[FULL_MESSAGE_LEN] = FULL_MESSAGE;
	uint32_t sendto_flags = 0;
	int64_t sent_bytes = syscall(__NR_sendto, client_socket_fd, sent_data, sizeof(sent_data), sendto_flags, (sockaddr*)&server_addr, sizeof(server_addr));
	assert_syscall_state(SYSCALL_SUCCESS, "sendto (client)", sent_bytes, NOT_EQUAL, -1);

	/* The server accepts the connection and receives the message */
	int connected_socket_fd = syscall(__NR_accept4, server_socket_fd, NULL, NULL, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "accept4 (server)", connected_socket_fd, NOT_EQUAL, -1);

	struct msghdr recv_msg;
	struct iovec iov[2];
	memset(&recv_msg, 0, sizeof(recv_msg));
	memset(iov, 0, sizeof(iov));
	recv_msg.msg_name = (sockaddr*)&client_addr;
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
		evt_test->assert_num_params_pushed(5);
		GTEST_SKIP() << "[RECVMSG_X]: what we receive is correct but we need to reimplement it, see the code" << std::endl;
	}

	/* Parameter 5: msg_control (type: PT_BYTEBUF) */
	evt_test->assert_empty_param(5);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
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

	/* Parameter 5: msg_control (type: PT_BYTEBUF) */
	evt_test->assert_empty_param(5);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

#endif

#ifdef __NR_getsockopt

#include <netdb.h>
#include <time.h>

#if defined(__NR_socket) && defined(__NR_setsockopt) && defined(__NR_close)
TEST(SyscallExit, socketcall_getsockoptX_success)
{
	auto evt_test = get_syscall_event_test(__NR_getsockopt, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t socketfd = syscall(__NR_socket, AF_INET, SOCK_DGRAM, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "socket", socketfd, NOT_EQUAL, -1);

	/* This option allow us to reuse the same address. */
	int32_t setsockopt_option_value = 1;
	socklen_t setsockopt_option_len = sizeof(setsockopt_option_value);

	unsigned long args[5] = {0};
	args[0] = socketfd;
	args[1] = SOL_SOCKET;
	args[2] = SO_REUSEADDR;
	args[3] = (unsigned long)&setsockopt_option_value;
	args[4] = setsockopt_option_len;
	assert_syscall_state(SYSCALL_SUCCESS, "setsockopt", syscall(__NR_socketcall, SYS_SETSOCKOPT, args), NOT_EQUAL, -1);

	/* Check if we are able to get the right option just set */
	int32_t level = SOL_SOCKET;
	int32_t option_name = SO_REUSEADDR;
	/* just a fake value that should be overwritten by the real value */
	int32_t option_value = 14;
	socklen_t option_len = sizeof(int32_t);

	args[0] = socketfd;
	args[1] = level;
	args[2] = option_name;
	args[3] = (unsigned long)&option_value;
	args[4] = (unsigned long)&option_len;
	assert_syscall_state(SYSCALL_SUCCESS, "getsockopt", syscall(__NR_socketcall, SYS_GETSOCKOPT, args), NOT_EQUAL, -1);

	/* Cleaning phase */
	syscall(__NR_close, socketfd);

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

	/* Parameter 2: fd (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)socketfd);

	/* Parameter 3: level (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(3, (uint8_t)PPM_SOCKOPT_LEVEL_SOL_SOCKET);

	/* Parameter 4: optname (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(4, (uint8_t)PPM_SOCKOPT_SO_REUSEADDR);

	/* Parameter 5: optval (type: PT_DYN) */
	evt_test->assert_setsockopt_val(5, PPM_SOCKOPT_IDX_UINT32, &setsockopt_option_value, setsockopt_option_len);

	/* Parameter 6: optlen (type: PT_UINT32) */
	evt_test->assert_numeric_param(6, (uint32_t)setsockopt_option_len);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(6);
}
#endif

TEST(SyscallExit, socketcall_getsockoptX_SO_RCVTIMEO)
{
	auto evt_test = get_syscall_event_test(__NR_getsockopt, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t mock_fd = -1;
	int32_t level = SOL_SOCKET;
	int32_t option_name = SO_RCVTIMEO;
	struct timeval option_value = {0};
	option_value.tv_sec = 5;
	option_value.tv_usec = 10;
	socklen_t option_len = sizeof(struct timeval);

	unsigned long args[5] = {0};
	args[0] = mock_fd;
	args[1] = level;
	args[2] = option_name;
	args[3] = (unsigned long)&option_value;
	args[4] = (unsigned long)&option_len;
	assert_syscall_state(SYSCALL_FAILURE, "getsockopt", syscall(__NR_socketcall, SYS_GETSOCKOPT, args));
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

	/* Parameter 2: fd (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)mock_fd);

	/* Parameter 3: level (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(3, (uint8_t)PPM_SOCKOPT_LEVEL_SOL_SOCKET);

	/* Parameter 4: optname (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(4, (uint8_t)PPM_SOCKOPT_SO_RCVTIMEO);

	/* Parameter 5: optval (type: PT_DYN) */
	uint64_t total_timeval = option_value.tv_sec * SEC_FACTOR + option_value.tv_usec * USEC_FACTOR;
	evt_test->assert_setsockopt_val(5, PPM_SOCKOPT_IDX_TIMEVAL, &total_timeval, option_len);

	/* Parameter 6: optlen (type: PT_UINT32) */
	evt_test->assert_numeric_param(6, (uint32_t)option_len);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(6);
}

TEST(SyscallExit, socketcall_getsockoptX_SO_COOKIE)
{
	auto evt_test = get_syscall_event_test(__NR_getsockopt, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t mock_fd = -1;
	int32_t level = SOL_SOCKET;
	int32_t option_name = SO_COOKIE;
	uint64_t option_value = 16;
	socklen_t option_len = sizeof(option_value);

	unsigned long args[5] = {0};
	args[0] = mock_fd;
	args[1] = level;
	args[2] = option_name;
	args[3] = (unsigned long)&option_value;
	args[4] = (unsigned long)&option_len;
	assert_syscall_state(SYSCALL_FAILURE, "getsockopt", syscall(__NR_socketcall, SYS_GETSOCKOPT, args));
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

	/* Parameter 2: fd (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)mock_fd);

	/* Parameter 3: level (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(3, (uint8_t)PPM_SOCKOPT_LEVEL_SOL_SOCKET);

	/* Parameter 4: optname (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(4, (uint8_t)PPM_SOCKOPT_SO_COOKIE);

	/* Parameter 5: optval (type: PT_DYN) */
	evt_test->assert_setsockopt_val(5, PPM_SOCKOPT_IDX_UINT64, &option_value, option_len);

	/* Parameter 6: optlen (type: PT_UINT32) */
	evt_test->assert_numeric_param(6, (uint32_t)option_len);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(6);
}

TEST(SyscallExit, socketcall_getsockoptX_SO_PASSCRED)
{
	auto evt_test = get_syscall_event_test(__NR_getsockopt, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t mock_fd = -1;
	int32_t level = SOL_SOCKET;
	int32_t option_name = SO_PASSCRED;
	uint32_t option_value = 16;
	socklen_t option_len = sizeof(option_value);

	unsigned long args[5] = {0};
	args[0] = mock_fd;
	args[1] = level;
	args[2] = option_name;
	args[3] = (unsigned long)&option_value;
	args[4] = (unsigned long)&option_len;
	assert_syscall_state(SYSCALL_FAILURE, "getsockopt", syscall(__NR_socketcall, SYS_GETSOCKOPT, args));
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

	/* Parameter 2: fd (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)mock_fd);

	/* Parameter 3: level (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(3, (uint8_t)PPM_SOCKOPT_LEVEL_SOL_SOCKET);

	/* Parameter 4: optname (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(4, (uint8_t)PPM_SOCKOPT_SO_PASSCRED);

	/* Parameter 5: optval (type: PT_DYN) */
	evt_test->assert_setsockopt_val(5, PPM_SOCKOPT_IDX_UINT32, &option_value, option_len);

	/* Parameter 6: optlen (type: PT_UINT32) */
	evt_test->assert_numeric_param(6, (uint32_t)option_len);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(6);
}

TEST(SyscallExit, socketcall_getsockoptX_UNKNOWN_OPTION)
{
	auto evt_test = get_syscall_event_test(__NR_getsockopt, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t mock_fd = -1;
	int32_t level = SOL_SOCKET;
	int32_t option_name = -1; /* this is an unknown option. */
	uint32_t option_value = 16;
	socklen_t option_len = sizeof(option_value);

	unsigned long args[5] = {0};
	args[0] = mock_fd;
	args[1] = level;
	args[2] = option_name;
	args[3] = (unsigned long)&option_value;
	args[4] = (unsigned long)&option_len;
	assert_syscall_state(SYSCALL_FAILURE, "getsockopt", syscall(__NR_socketcall, SYS_GETSOCKOPT, args));
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

	/* Parameter 2: fd (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)mock_fd);

	/* Parameter 3: level (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(3, (uint8_t)PPM_SOCKOPT_LEVEL_SOL_SOCKET);

	/* Parameter 4: optname (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(4, (uint8_t)PPM_SOCKOPT_UNKNOWN);

	/* Parameter 5: optval (type: PT_DYN) */
	evt_test->assert_setsockopt_val(5, PPM_SOCKOPT_IDX_UNKNOWN, &option_value, option_len);

	/* Parameter 6: optlen (type: PT_UINT32) */
	evt_test->assert_numeric_param(6, (uint32_t)option_len);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(6);
}

TEST(SyscallExit, socketcall_getsockoptX_SOL_UNKNOWN)
{
	auto evt_test = get_syscall_event_test(__NR_getsockopt, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t mock_fd = -1;
	int32_t level = 7; /* Unknown level. */
	int32_t option_name = SO_PASSCRED;
	uint32_t option_value = 16;
	socklen_t option_len = sizeof(option_value);

	unsigned long args[5] = {0};
	args[0] = mock_fd;
	args[1] = level;
	args[2] = option_name;
	args[3] = (unsigned long)&option_value;
	args[4] = (unsigned long)&option_len;
	assert_syscall_state(SYSCALL_FAILURE, "getsockopt", syscall(__NR_socketcall, SYS_GETSOCKOPT, args));
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

	/* Parameter 2: fd (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)mock_fd);

	/* Parameter 3: level (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(3, (uint8_t)PPM_SOCKOPT_LEVEL_UNKNOWN);

	/* Parameter 4: optname (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(4, (uint8_t)PPM_SOCKOPT_LEVEL_UNKNOWN);

	/* Parameter 5: optval (type: PT_DYN) */
	evt_test->assert_setsockopt_val(5, PPM_SOCKOPT_IDX_UNKNOWN, &option_value, option_len);

	/* Parameter 6: optlen (type: PT_UINT32) */
	evt_test->assert_numeric_param(6, (uint32_t)option_len);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(6);
}

TEST(SyscallExit, socketcall_getsockoptX_ZERO_OPTLEN)
{
	auto evt_test = get_syscall_event_test(__NR_getsockopt, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t mock_fd = -1;
	int32_t level = 7; /* Unknown level. */
	int32_t option_name = SO_PASSCRED;
	uint32_t option_value = 0;
	socklen_t option_len = 0;

	unsigned long args[5] = {0};
	args[0] = mock_fd;
	args[1] = level;
	args[2] = option_name;
	args[3] = (unsigned long)&option_value;
	args[4] = (unsigned long)&option_len;
	assert_syscall_state(SYSCALL_FAILURE, "getsockopt", syscall(__NR_socketcall, SYS_GETSOCKOPT, args));
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

	/* Parameter 2: fd (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)mock_fd);

	/* Parameter 3: level (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(3, (uint8_t)PPM_SOCKOPT_LEVEL_UNKNOWN);

	/* Parameter 4: optname (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(4, (uint8_t)PPM_SOCKOPT_LEVEL_UNKNOWN);

	/* Parameter 5: optval (type: PT_DYN) */
	evt_test->assert_setsockopt_val(5, PPM_SOCKOPT_IDX_UNKNOWN, &option_value, option_len);

	/* Parameter 6: optlen (type: PT_UINT32) */
	evt_test->assert_numeric_param(6, (uint32_t)option_len);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(6);
}

#endif

#ifdef __NR_setsockopt

#include <netdb.h>
#include <time.h>

TEST(SyscallExit, socketcall_setsockoptX_SO_ERROR)
{
	auto evt_test = get_syscall_event_test(__NR_setsockopt, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t mock_fd = -1;
	int32_t level = SOL_SOCKET;
	int32_t option_name = SO_ERROR;
	int32_t option_value = 14;
	socklen_t option_len = sizeof(int32_t);

	unsigned long args[5] = {0};
	args[0] = mock_fd;
	args[1] = level;
	args[2] = option_name;
	args[3] = (unsigned long)&option_value;
	args[4] = option_len;
	assert_syscall_state(SYSCALL_FAILURE, "setsockopt", syscall(__NR_socketcall, SYS_SETSOCKOPT, args));
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

	/* Parameter 2: fd (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)mock_fd);

	/* Parameter 3: level (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(3, (uint8_t)PPM_SOCKOPT_LEVEL_SOL_SOCKET);

	/* Parameter 4: optname (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(4, (uint8_t)PPM_SOCKOPT_SO_ERROR);

	/* Parameter 5: optval (type: PT_DYN) */
	/* In case of `PPM_SOCKOPT_IDX_ERRNO` we receive the negative `option_value`*/
	int64_t negative_option_value = -option_value;
	evt_test->assert_setsockopt_val(5, PPM_SOCKOPT_IDX_ERRNO, &negative_option_value, option_len);

	/* Parameter 6: optlen (type: PT_UINT32) */
	evt_test->assert_numeric_param(6, (uint32_t)option_len);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(6);
}

TEST(SyscallExit, socketcall_setsockoptX_SO_RCVTIMEO)
{
	auto evt_test = get_syscall_event_test(__NR_setsockopt, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t mock_fd = -1;
	int32_t level = SOL_SOCKET;
	int32_t option_name = SO_RCVTIMEO;
	struct timeval option_value = {0};
	option_value.tv_sec = 5;
	option_value.tv_usec = 10;
	socklen_t option_len = sizeof(struct timeval);

	unsigned long args[5] = {0};
	args[0] = mock_fd;
	args[1] = level;
	args[2] = option_name;
	args[3] = (unsigned long)&option_value;
	args[4] = option_len;
	assert_syscall_state(SYSCALL_FAILURE, "setsockopt", syscall(__NR_socketcall, SYS_SETSOCKOPT, args));
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

	/* Parameter 2: fd (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)mock_fd);

	/* Parameter 3: level (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(3, (uint8_t)PPM_SOCKOPT_LEVEL_SOL_SOCKET);

	/* Parameter 4: optname (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(4, (uint8_t)PPM_SOCKOPT_SO_RCVTIMEO);

	/* Parameter 5: optval (type: PT_DYN) */
	uint64_t total_timeval = option_value.tv_sec * SEC_FACTOR + option_value.tv_usec * USEC_FACTOR;
	evt_test->assert_setsockopt_val(5, PPM_SOCKOPT_IDX_TIMEVAL, &total_timeval, option_len);

	/* Parameter 6: optlen (type: PT_UINT32) */
	evt_test->assert_numeric_param(6, (uint32_t)option_len);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(6);
}

TEST(SyscallExit, socketcall_setsockoptX_SO_COOKIE)
{
	auto evt_test = get_syscall_event_test(__NR_setsockopt, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t mock_fd = -1;
	int32_t level = SOL_SOCKET;
	int32_t option_name = SO_COOKIE;
	uint64_t option_value = 16;
	socklen_t option_len = sizeof(option_value);

	unsigned long args[5] = {0};
	args[0] = mock_fd;
	args[1] = level;
	args[2] = option_name;
	args[3] = (unsigned long)&option_value;
	args[4] = option_len;
	assert_syscall_state(SYSCALL_FAILURE, "setsockopt", syscall(__NR_socketcall, SYS_SETSOCKOPT, args));
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

	/* Parameter 2: fd (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)mock_fd);

	/* Parameter 3: level (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(3, (uint8_t)PPM_SOCKOPT_LEVEL_SOL_SOCKET);

	/* Parameter 4: optname (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(4, (uint8_t)PPM_SOCKOPT_SO_COOKIE);

	/* Parameter 5: optval (type: PT_DYN) */
	evt_test->assert_setsockopt_val(5, PPM_SOCKOPT_IDX_UINT64, &option_value, option_len);

	/* Parameter 6: optlen (type: PT_UINT32) */
	evt_test->assert_numeric_param(6, (uint32_t)option_len);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(6);
}

TEST(SyscallExit, socketcall_setsockoptX_SO_PASSCRED)
{
	auto evt_test = get_syscall_event_test(__NR_setsockopt, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t mock_fd = -1;
	int32_t level = SOL_SOCKET;
	int32_t option_name = SO_PASSCRED;
	uint32_t option_value = 16;
	socklen_t option_len = sizeof(option_value);

	unsigned long args[5] = {0};
	args[0] = mock_fd;
	args[1] = level;
	args[2] = option_name;
	args[3] = (unsigned long)&option_value;
	args[4] = option_len;
	assert_syscall_state(SYSCALL_FAILURE, "setsockopt", syscall(__NR_socketcall, SYS_SETSOCKOPT, args));
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

	/* Parameter 2: fd (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)mock_fd);

	/* Parameter 3: level (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(3, (uint8_t)PPM_SOCKOPT_LEVEL_SOL_SOCKET);

	/* Parameter 4: optname (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(4, (uint8_t)PPM_SOCKOPT_SO_PASSCRED);

	/* Parameter 5: optval (type: PT_DYN) */
	evt_test->assert_setsockopt_val(5, PPM_SOCKOPT_IDX_UINT32, &option_value, option_len);

	/* Parameter 6: optlen (type: PT_UINT32) */
	evt_test->assert_numeric_param(6, (uint32_t)option_len);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(6);
}

TEST(SyscallExit, socketcall_setsockoptX_UNKNOWN_OPTION)
{
	auto evt_test = get_syscall_event_test(__NR_setsockopt, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t mock_fd = -1;
	int32_t level = SOL_SOCKET;
	int32_t option_name = -1; /* this is an unknown option. */
	uint32_t option_value = 16;
	socklen_t option_len = sizeof(option_value);

	unsigned long args[5] = {0};
	args[0] = mock_fd;
	args[1] = level;
	args[2] = option_name;
	args[3] = (unsigned long)&option_value;
	args[4] = option_len;
	assert_syscall_state(SYSCALL_FAILURE, "setsockopt", syscall(__NR_socketcall, SYS_SETSOCKOPT, args));
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

	/* Parameter 2: fd (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)mock_fd);

	/* Parameter 3: level (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(3, (uint8_t)PPM_SOCKOPT_LEVEL_SOL_SOCKET);

	/* Parameter 4: optname (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(4, (uint8_t)PPM_SOCKOPT_UNKNOWN);

	/* Parameter 5: optval (type: PT_DYN) */
	evt_test->assert_setsockopt_val(5, PPM_SOCKOPT_IDX_UNKNOWN, &option_value, option_len);

	/* Parameter 6: optlen (type: PT_UINT32) */
	evt_test->assert_numeric_param(6, (uint32_t)option_len);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(6);
}

TEST(SyscallExit, socketcall_setsockoptX_SOL_UNKNOWN)
{
	auto evt_test = get_syscall_event_test(__NR_setsockopt, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t mock_fd = -1;
	int32_t level = 7; /* Unknown level. */
	int32_t option_name = SO_PASSCRED;
	uint32_t option_value = 16;
	socklen_t option_len = sizeof(option_value);

	unsigned long args[5] = {0};
	args[0] = mock_fd;
	args[1] = level;
	args[2] = option_name;
	args[3] = (unsigned long)&option_value;
	args[4] = option_len;
	assert_syscall_state(SYSCALL_FAILURE, "setsockopt", syscall(__NR_socketcall, SYS_SETSOCKOPT, args));
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

	/* Parameter 2: fd (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)mock_fd);

	/* Parameter 3: level (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(3, (uint8_t)PPM_SOCKOPT_LEVEL_UNKNOWN);

	/* Parameter 4: optname (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(4, (uint8_t)PPM_SOCKOPT_LEVEL_UNKNOWN);

	/* Parameter 5: optval (type: PT_DYN) */
	evt_test->assert_setsockopt_val(5, PPM_SOCKOPT_IDX_UNKNOWN, &option_value, option_len);

	/* Parameter 6: optlen (type: PT_UINT32) */
	evt_test->assert_numeric_param(6, (uint32_t)option_len);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(6);
}

TEST(SyscallExit, socketcall_setsockoptX_ZERO_OPTLEN)
{
	auto evt_test = get_syscall_event_test(__NR_setsockopt, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t mock_fd = -1;
	int32_t level = 7; /* Unknown level. */
	int32_t option_name = SO_PASSCRED;
	uint32_t option_value = 0;
	socklen_t option_len = 0;

	unsigned long args[5] = {0};
	args[0] = mock_fd;
	args[1] = level;
	args[2] = option_name;
	args[3] = (unsigned long)&option_value;
	args[4] = option_len;
	assert_syscall_state(SYSCALL_FAILURE, "setsockopt", syscall(__NR_socketcall, SYS_SETSOCKOPT, args));
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

	/* Parameter 2: fd (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)mock_fd);

	/* Parameter 3: level (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(3, (uint8_t)PPM_SOCKOPT_LEVEL_UNKNOWN);

	/* Parameter 4: optname (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(4, (uint8_t)PPM_SOCKOPT_LEVEL_UNKNOWN);

	/* Parameter 5: optval (type: PT_DYN) */
	evt_test->assert_setsockopt_val(5, PPM_SOCKOPT_IDX_UNKNOWN, &option_value, option_len);

	/* Parameter 6: optlen (type: PT_UINT32) */
	evt_test->assert_numeric_param(6, (uint32_t)option_len);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(6);
}

#endif

#ifdef __NR_send

TEST(SyscallExit, socketcall_sendX)
{
	auto evt_test = get_syscall_event_test(__NR_send, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t mock_fd = -1;
	const unsigned data_len = DEFAULT_SNAPLEN * 2;
	char buf[data_len] = "some-data";
	int flags = 0;

	unsigned long args[4] = {0};
	args[0] = mock_fd;
	args[1] = (unsigned long)buf;
	args[2] = data_len;
	args[3] = (unsigned long)flags;
	assert_syscall_state(SYSCALL_FAILURE, "send", syscall(__NR_socketcall, SYS_SEND, args));
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
	evt_test->assert_bytebuf_param(2, buf, DEFAULT_SNAPLEN);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}
#endif

#ifdef __NR_recv
TEST(SyscallExit, socketcall_recvX_fail)
{
	auto evt_test = get_syscall_event_test(__NR_recv, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t mock_fd = -1;
	char *mock_buf = NULL;
	size_t mock_count = DEFAULT_SNAPLEN;
	int flags = 0;

	unsigned long args[4] = {0};
	args[0] = mock_fd;
	args[1] = (unsigned long)mock_buf;
	args[2] = mock_count;
	args[3] = (unsigned long)flags;
	assert_syscall_state(SYSCALL_FAILURE, "recv", syscall(__NR_socketcall, SYS_RECV, args));
	int errno_value = -errno;

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

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}
#endif

#ifdef __NR_getpeername
TEST(SyscallExit, socketcall_getpeernameX)
{
	auto evt_test = get_syscall_event_test(__NR_getpeername, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t mock_fd = -1;
	void *usockaddr = NULL;
	int *usockaddr_len = NULL;

	unsigned long args[3] = {0};
	args[0] = mock_fd;
	args[1] = (unsigned long)usockaddr;
	args[2] = (unsigned long)usockaddr_len;
	assert_syscall_state(SYSCALL_FAILURE, "getpeername", syscall(__NR_socketcall, SYS_GETPEERNAME, args));

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

#ifdef __NR_getsockname
TEST(SyscallExit, socketcall_getsocknameX)
{
	auto evt_test = get_syscall_event_test(__NR_getsockname, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t mock_fd = -1;
	void *usockaddr = NULL;
	int *usockaddr_len = NULL;

	unsigned long args[3] = {0};
	args[0] = mock_fd;
	args[1] = (unsigned long)usockaddr;
	args[2] = (unsigned long)usockaddr_len;
	assert_syscall_state(SYSCALL_FAILURE, "getsockname", syscall(__NR_socketcall, SYS_GETSOCKNAME, args));

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

TEST(SyscallExit, socketcall_wrong_code_socketcall_interesting)
{
	// Even if the socketcall is marked as interesting we drop the event
	auto evt_test = get_syscall_event_test(__NR_socketcall, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	unsigned long args[3] = {0};
	args[0] = 47;
	args[1] = 0;
	args[2] = 0;
	int wrong_code = 1230;

	assert_syscall_state(SYSCALL_FAILURE, "socketcall", syscall(__NR_socketcall, wrong_code, args));

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_absence(CURRENT_PID, PPME_GENERIC_X);
}

TEST(SyscallExit, socketcall_wrong_code_socketcall_not_interesting)
{
	// Same as the previous test
	auto evt_test = get_syscall_event_test(__NR_setsockopt, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	unsigned long args[3] = {0};
	args[0] = 47;
	args[1] = 0;
	args[2] = 0;
	int wrong_code = 1230;

	assert_syscall_state(SYSCALL_FAILURE, "socketcall", syscall(__NR_socketcall, wrong_code, args));

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_absence(CURRENT_PID, PPME_GENERIC_X);
}

TEST(SyscallExit, socketcall_null_pointer)
{
	auto evt_test = get_syscall_event_test(__NR_shutdown, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	assert_syscall_state(SYSCALL_FAILURE, "socketcall", syscall(__NR_socketcall, SYS_SHUTDOWN, NULL));
	int64_t errno_value = -errno;

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	if(evt_test->is_kmod_engine())
	{
		/* with a null pointer we are not able to correctly obtain the event so right now we drop it. */
		evt_test->assert_event_absence();
		SUCCEED();
		return;
	}

	/* in bpf and modern bpf we can obtain an event even with a null pointer. */
	evt_test->assert_event_presence();

	if(HasFatalFailure())
	{
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: ret (type: PT_FD)*/
	/* Here we can obtain this param even with a null pointer
	 * because this is the return value.
	 */
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}

TEST(SyscallExit, socketcall_null_pointer_and_wrong_code_socketcall_interesting)
{
	// We send a wrong code so the event will be dropped
	auto evt_test = get_syscall_event_test(__NR_socketcall, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int wrong_code = 1230;
	assert_syscall_state(SYSCALL_FAILURE, "socketcall", syscall(__NR_socketcall, wrong_code, NULL));

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_absence(CURRENT_PID, PPME_GENERIC_X);
}

#endif /* __NR_socketcall */

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
#endif

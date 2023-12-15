#include "../../event_class/event_class.h"

#ifdef __NR_socketcall

#if defined(__NR_socket) && defined(__NR_bind) && defined(__NR_connect)

#include <sys/socket.h>
#include <linux/net.h>

#if defined(__NR_clone3) && defined(__NR_wait4)
#include <linux/sched.h>

TEST(SyscallEnter, socketcall_socketE)
{
	auto evt_test = get_syscall_event_test(__NR_socket, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	unsigned long args[3] = {0};
	args[0] = AF_INET;
	args[1] = SOCK_RAW;
	args[2] = PF_INET;

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
			exit(EXIT_FAILURE);
		}
		else
		{
			exit(EXIT_SUCCESS);
		}
	}

	assert_syscall_state(SYSCALL_SUCCESS, "clone3", ret_pid, NOT_EQUAL, -1);
	/* Catch the child before doing anything else. */
	int status = 0;
	int options = 0;
	assert_syscall_state(SYSCALL_SUCCESS, "wait4", syscall(__NR_wait4, ret_pid, &status, options, NULL), NOT_EQUAL, -1);

	if(__WEXITSTATUS(status) == EXIT_FAILURE || __WIFSIGNALED(status) != 0)
	{
		FAIL() << "The 'socketcall socket' failed while it should be successful..." << std::endl;
	}

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

	/* Parameter 1: domain (type: PT_ENUMFLAGS32) */
	evt_test->assert_numeric_param(1, (uint32_t)PPM_AF_INET);

	/* Parameter 2: type (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (uint32_t)args[1]);

	/* Parameter 3: proto (type: PT_UINT32) */
	evt_test->assert_numeric_param(3, (uint32_t)args[2]);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}
#endif

TEST(SyscallEnter, socketcall_bindE)
{
	auto evt_test = get_syscall_event_test(__NR_bind, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	unsigned long args[3] = {0};
	args[0] = 47;
	args[1] = 0;
	args[2] = 0;

	assert_syscall_state(SYSCALL_FAILURE, "socketcall bind", syscall(__NR_socketcall, SYS_BIND, args));

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
	evt_test->assert_numeric_param(1, (int64_t)args[0]);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}

TEST(SyscallEnter, socketcall_connectE)
{
	auto evt_test = get_syscall_event_test(__NR_connect, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t mock_fd = -1;
	sockaddr_in server_addr;
	evt_test->server_fill_sockaddr_in(&server_addr);
	unsigned long args[3] = {0};
	args[0] = mock_fd;
	args[1] = (unsigned long)&server_addr;
	args[2] = sizeof(server_addr);
	assert_syscall_state(SYSCALL_FAILURE, "socketcall connect", syscall(__NR_socketcall, SYS_CONNECT, args));

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
	evt_test->assert_numeric_param(1, (int64_t)mock_fd);

	/* Parameter 2: addr (type: PT_SOCKADDR)*/
	/* Modern BPF returns addr_info even if the syscall fails other drivers return an empty param. */
	if(evt_test->is_modern_bpf_engine())
	{
		evt_test->assert_addr_info_inet_param(2, PPM_AF_INET, IPV4_SERVER, IPV4_PORT_SERVER_STRING);
	}
	else
	{
		evt_test->assert_empty_param(2);
		evt_test->assert_num_params_pushed(2);
		GTEST_SKIP() << "[CONNECT_E]: what we receive is correct but we need to reimplement it, see the code" << std::endl;
	}

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}
#endif

#ifdef __NR_recvmmsg
TEST(SyscallEnter, socketcall_recvmmsgE)
{
	auto evt_test = get_syscall_event_test(__NR_recvmmsg, ENTER_EVENT);

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
TEST(SyscallEnter, socketcall_sendmmsgE)
{
	auto evt_test = get_syscall_event_test(__NR_sendmmsg, ENTER_EVENT);

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

TEST(SyscallEnter, socketcall_shutdownE)
{
	auto evt_test = get_syscall_event_test(__NR_shutdown, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t invalid_fd = -1;
	int how = SHUT_RD;

	unsigned long args[2] = {0};
	args[0] = invalid_fd;
	args[1] = how;
	assert_syscall_state(SYSCALL_FAILURE, "shutdown", syscall(__NR_socketcall, SYS_SHUTDOWN, args));

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

	/* Parameter 1: fd (type: PT_FD) */
	evt_test->assert_numeric_param(1, (int64_t)invalid_fd);

	/* Parameter 2: how (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(2, (uint8_t)PPM_SHUT_RD);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

#if defined(__NR_accept) || defined(__s390x__)

TEST(SyscallEnter, socketcall_acceptE)
{
#ifdef __s390x__
	auto evt_test = get_syscall_event_test(__NR_accept4, ENTER_EVENT);
	/* The kmod/bpf can correctly handle accept also on s390x */
	if(evt_test->is_kmod_engine() || evt_test->is_bpf_engine())
	{
		/* we cannot set `__NR_accept` explicitly since it is not defined on s390x
		 * we activate all syscalls.
		 */
		evt_test.reset(get_syscall_event_test().release());
		evt_test->set_event_type(PPME_SOCKET_ACCEPT_5_E);
	}
#else
	auto evt_test = get_syscall_event_test(__NR_accept, ENTER_EVENT);
#endif

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t mock_fd = -1;
	sockaddr* addr = NULL;
	socklen_t *addrlen = NULL;

	unsigned long args[3] = {0};
	args[0] = mock_fd;
	args[1] = (unsigned long)addr;
	args[2] = (unsigned long)addrlen;
	assert_syscall_state(SYSCALL_FAILURE, "accept", syscall(__NR_socketcall, SYS_ACCEPT, args));

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure())
	{
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

#ifdef __s390x__
	if(evt_test->is_modern_bpf_engine())
	{
		/* socketcall uses accept4 event for SYS_ACCEPT for modern BPF */

		/*=============================== ASSERT PARAMETERS  ===========================*/

		/* Parameter 1: flags (type: PT_FLAGS32) */
		/* Right now `flags` are not supported so we will catch always `0` */
		evt_test->assert_numeric_param(1, (uint32_t)0);

		/*=============================== ASSERT PARAMETERS  ===========================*/

		evt_test->assert_num_params_pushed(1);
		SUCCEED();
	}
#else
	/*=============================== ASSERT PARAMETERS  ===========================*/

	// Here we have no parameters to assert.

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(0);
#endif
}

#endif /* __NR_accept || __s390x__ */

#ifdef __NR_accept4

TEST(SyscallEnter, socketcall_accept4E)
{
	auto evt_test = get_syscall_event_test(__NR_accept4, ENTER_EVENT);

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

	/* Parameter 1: flags (type: PT_FLAGS32) */
	/* Right now `flags` are not supported so we will catch always `0` */
	evt_test->assert_numeric_param(1, (uint32_t)0);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif

#ifdef __NR_listen
TEST(SyscallEnter, socketcall_listenE)
{
	auto evt_test = get_syscall_event_test(__NR_listen, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t socket_fd = 2;
	int backlog = 3;

	unsigned long args[2] = {0};
	args[0] = socket_fd;
	args[1] = backlog;
	assert_syscall_state(SYSCALL_FAILURE, "listen", syscall(__NR_socketcall, SYS_LISTEN, args));

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
	evt_test->assert_numeric_param(1, (int64_t)socket_fd);

	/* Parameter 2: backlog (type: PT_INT32) */
	evt_test->assert_numeric_param(2, (int32_t)backlog);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}
#endif

#ifdef __NR_recvfrom

TEST(SyscallEnter, socketcall_recvfromE)
{
	auto evt_test = get_syscall_event_test(__NR_recvfrom, ENTER_EVENT);

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
	evt_test->assert_numeric_param(1, (int64_t)mock_fd);

	/* Parameter 2: size (type: PT_UINT32)*/
	evt_test->assert_numeric_param(2, (uint32_t)received_data_len);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}
#endif

#ifdef __NR_socketpair

#include <sys/socket.h>

TEST(SyscallEnter, socketcall_socketpairE)
{
	auto evt_test = get_syscall_event_test(__NR_socketpair, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int domain = PF_LOCAL;
	int type = SOCK_STREAM;
	int protocol = 0;
	int32_t *fds = NULL;

	unsigned long args[4] = {0};
	args[0] = domain;
	args[1] = type;
	args[2] = protocol;
	args[3] = (unsigned long)fds;
	assert_syscall_state(SYSCALL_FAILURE, "socketpair", syscall(__NR_socketcall, SYS_SOCKETPAIR, args));

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

	/* Parameter 1: domain (type: PT_ENUMFLAGS32) */
	evt_test->assert_numeric_param(1, (uint32_t)PPM_AF_LOCAL);

	/* Parameter 2: type (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (uint32_t)type);

	/* Parameter 3: proto (type: PT_UINT32) */
	evt_test->assert_numeric_param(3, (uint32_t)protocol);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}
#endif

#if defined(__NR_connect) && defined(__NR_socket) && defined(__NR_bind) && defined(__NR_listen) && defined(__NR_close) && defined(__NR_setsockopt) && defined(__NR_shutdown) && defined(__NR_sendto)

TEST(SyscallEnter, socketcall_sendtoE)
{
	auto evt_test = get_syscall_event_test(__NR_sendto, ENTER_EVENT);

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
	assert_syscall_state(SYSCALL_SUCCESS, "sendto (client)", syscall(__NR_socketcall, SYS_SENDTO, args), NOT_EQUAL, -1);

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

	/* Parameter 1: fd (type: PT_FD) */
	evt_test->assert_numeric_param(1, (int64_t)client_socket_fd);

	/* Parameter 2: size (type: PT_UINT32)*/
	evt_test->assert_numeric_param(2, (uint32_t)FULL_MESSAGE_LEN);

	/* Parameter 3: addr (type: PT_SOCKADDR)*/
	/* The client performs a `sendto` to the server so the src_ipv4 is the client one. */
	evt_test->assert_tuple_inet_param(3, PPM_AF_INET, IPV4_CLIENT, IPV4_SERVER, IPV4_PORT_CLIENT_STRING, IPV4_PORT_SERVER_STRING);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}
#endif

#if defined(__NR_connect) && defined(__NR_socket) && defined(__NR_bind) && defined(__NR_listen) && defined(__NR_close) && defined(__NR_setsockopt) && defined(__NR_shutdown) && defined(__NR_sendmsg)

TEST(SyscallEnter, socketcall_sendmsgE)
{
	auto evt_test = get_syscall_event_test(__NR_sendmsg, ENTER_EVENT);

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
	assert_syscall_state(SYSCALL_SUCCESS, "sendmsg (client)", syscall(__NR_socketcall, SYS_SENDMSG, args), NOT_EQUAL, -1);

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

	/* Parameter 1: fd (type: PT_FD) */
	evt_test->assert_numeric_param(1, (int64_t)client_socket_fd);

	/* Parameter 2: size (type: PT_UINT32)*/
	evt_test->assert_numeric_param(2, (uint32_t)FULL_MESSAGE_LEN);

	/* Parameter 3: addr (type: PT_SOCKADDR)*/
	/* The client performs a `sendmsg` to the server so the src_ipv4 is the client one. */
	evt_test->assert_tuple_inet_param(3, PPM_AF_INET, IPV4_CLIENT, IPV4_SERVER, IPV4_PORT_CLIENT_STRING, IPV4_PORT_SERVER_STRING);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}
#endif

#ifdef __NR_recvmsg
TEST(SyscallEnter, socketcall_recvmsgE)
{
	auto evt_test = get_syscall_event_test(__NR_recvmsg, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t mock_fd = -1;
	struct msghdr *msg = NULL;
	int flags = 0;

	unsigned long args[3] = {0};
	args[0] = mock_fd;
	args[1] = (unsigned long)msg;
	args[2] = flags;
	assert_syscall_state(SYSCALL_FAILURE, "recvmsg", syscall(__NR_socketcall, SYS_RECVMSG, args));

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

	/* Parameter 1: fd (type: PT_FD) */
	evt_test->assert_numeric_param(1, (int64_t)mock_fd);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif

#ifdef __NR_getsockopt

#include <netdb.h>

TEST(SyscallEnter, socketcall_getsockoptE)
{
	auto evt_test = get_syscall_event_test(__NR_getsockopt, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int socket_fd = 0;
	int level = 0;
	int option_name = 0;
	int option_value = 0;
	socklen_t option_len = 0;

	unsigned long args[5] = {0};
	args[0] = socket_fd;
	args[1] = level;
	args[2] = option_name;
	args[3] = (unsigned long)&option_value;
	args[4] = (unsigned long)&option_len;
	assert_syscall_state(SYSCALL_FAILURE, "getsockopt", syscall(__NR_socketcall, SYS_GETSOCKOPT, args));

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

#ifdef __NR_setsockopt

#include <netdb.h>

TEST(SyscallEnter, socketcall_setsockoptE)
{
	auto evt_test = get_syscall_event_test(__NR_setsockopt, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int socket_fd = 0;
	int level = 0;
	int option_name = 0;
	const void *option_value = NULL;
	socklen_t option_len = 0;

	unsigned long args[5] = {0};
	args[0] = socket_fd;
	args[1] = level;
	args[2] = option_name;
	args[3] = (unsigned long)option_value;
	args[4] = option_len;
	assert_syscall_state(SYSCALL_FAILURE, "setsockopt", syscall(__NR_socketcall, SYS_SETSOCKOPT, args));

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

#ifdef __NR_send

TEST(SyscallEnter, socketcall_sendE)
{
	auto evt_test = get_syscall_event_test(__NR_send, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t mock_fd = -1;
	char mock_buf[8];
	size_t mock_count = 4096;
	int flags = 0;

	unsigned long args[4] = {0};
	args[0] = mock_fd;
	args[1] = (unsigned long)mock_buf;
	args[2] = mock_count;
	args[3] = (unsigned long)flags;
	assert_syscall_state(SYSCALL_FAILURE, "send", syscall(__NR_socketcall, SYS_SEND, args));

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
	evt_test->assert_numeric_param(1, (int64_t)mock_fd);

	/* Parameter 2: size (type: PT_UINT32)*/
	evt_test->assert_numeric_param(2, (uint32_t)mock_count);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}
#endif

#ifdef __NR_recv

TEST(SyscallEnter, socketcall_recvE)
{
	auto evt_test = get_syscall_event_test(__NR_recv, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

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
	evt_test->assert_numeric_param(1, (int64_t)mock_fd);

	/* Parameter 2: size (type: PT_UINT32)*/
	evt_test->assert_numeric_param(2, (uint32_t)mock_count);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}
#endif

#ifdef __NR_getpeername
TEST(SyscallEnter, socketcall_getpeernameE)
{
	auto evt_test = get_syscall_event_test(__NR_getpeername, ENTER_EVENT);

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
TEST(SyscallEnter, socketcall_getsocknameE)
{
	auto evt_test = get_syscall_event_test(__NR_getsockname, ENTER_EVENT);

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

TEST(SyscallEnter, socketcall_wrong_code_socketcall_interesting)
{
	// We send a wrong code so the event will be dropped
	auto evt_test = get_syscall_event_test(__NR_socketcall, ENTER_EVENT);

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

	evt_test->assert_event_absence(CURRENT_PID, PPME_GENERIC_E);
}

TEST(SyscallEnter, socketcall_wrong_code_socketcall_not_interesting)
{
	// Same as the previous test
	auto evt_test = get_syscall_event_test(__NR_setsockopt, ENTER_EVENT);

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

	evt_test->assert_event_absence(CURRENT_PID, PPME_GENERIC_E);
}

TEST(SyscallEnter, socketcall_null_pointer)
{
	auto evt_test = get_syscall_event_test(__NR_shutdown, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	assert_syscall_state(SYSCALL_FAILURE, "socketcall", syscall(__NR_socketcall, SYS_SHUTDOWN, NULL));

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	if(evt_test->is_kmod_engine())
	{
		/* with a null pointer we are not able to correctly obtain the event so right now we drop it. */
		evt_test->assert_event_absence();
		SUCCEED();
		return;
	}

	/* in bpf and modern bpf we can obtain an event even with a null pointer, but
	 * all parameters will be 0.
	 */
	evt_test->assert_event_presence();

	if(HasFatalFailure())
	{
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: fd (type: PT_FD) */
	evt_test->assert_numeric_param(1, (int64_t)0);

	/* Parameter 2: how (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(2, (uint8_t)0);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

TEST(SyscallEnter, socketcall_null_pointer_and_wrong_code_socketcall_interesting)
{
	// We send a wrong code so the event will be dropped
	auto evt_test = get_syscall_event_test(__NR_socketcall, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int wrong_code = 1230;
	assert_syscall_state(SYSCALL_FAILURE, "socketcall", syscall(__NR_socketcall, wrong_code, NULL));

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_absence(CURRENT_PID, PPME_GENERIC_E);
}

#endif /* __NR_socketcall */

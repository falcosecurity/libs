#include "../../event_class/event_class.h"

#if defined(__NR_socketcall) && defined(__NR_socket) && defined(__NR_bind) && defined(__NR_connect)

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
	struct clone_args cl_args = {0};
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
	struct sockaddr_in server_addr;
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
	if(evt_test->is_kmod_engine())
		GTEST_SKIP() << "[acceptE] kmod socketcall implementation is event based (rather syscall) " << std::endl;
#else
	auto evt_test = get_syscall_event_test(__NR_accept, ENTER_EVENT);
#endif
	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t mock_fd = -1;
	struct sockaddr *addr = NULL;
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
	/* socketcall uses accept4 event for SYS_ACCEPT */

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: flags (type: PT_FLAGS32) */
	/* Right now `flags` are not supported so we will catch always `0` */
	evt_test->assert_numeric_param(1, (uint32_t)0);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
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
	struct sockaddr *addr = NULL;
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

	/* Parameter 2: backlog (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (uint32_t)backlog);

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
	int32_t* fds = NULL;

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

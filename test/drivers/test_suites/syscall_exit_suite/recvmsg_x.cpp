#include "../../event_class/event_class.h"

#ifdef __NR_recvmsg

#if defined(__NR_accept4) && defined(__NR_connect) && defined(__NR_socket) && defined(__NR_bind) && defined(__NR_listen) && defined(__NR_close) && defined(__NR_setsockopt) && defined(__NR_shutdown) && defined(__NR_sendto) && defined(__NR_sendmsg)

TEST(SyscallExit, recvmsgX_tcp_connection_no_snaplen)
{
	auto evt_test = get_syscall_event_test(__NR_recvmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_socket_fd = 0;
	int32_t server_socket_fd = 0;
	sockaddr_in client_addr = {};
	sockaddr_in server_addr = {};
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

	int64_t received_bytes = syscall(__NR_recvmsg, connected_socket_fd, &recv_msg, recvmsg_flags);
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
		/// TODO: If the socket is connected, the msg_name and msg_namelen members shall be ignored, but
		/// right now we use them to send data also in TCP connections so we need to change this behavior!
		evt_test->assert_empty_param(4);
		evt_test->assert_num_params_pushed(5);
		GTEST_SKIP() << "[RECVMSG_X]: we receive an empty tuple but we have all the data in the kernel to obtain the correct tuple" << std::endl;
	}

	/* Parameter 5: msg_control (type: PT_BYTEBUF) */
	evt_test->assert_empty_param(5);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

TEST(SyscallExit, recvmsgX_tcp_connection_snaplen)
{
	auto evt_test = get_syscall_event_test(__NR_recvmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_socket_fd = 0;
	int32_t server_socket_fd = 0;
	sockaddr_in client_addr = {};
	sockaddr_in server_addr = {};
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

	int64_t received_bytes = syscall(__NR_recvmsg, connected_socket_fd, &recv_msg, recvmsg_flags);
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
		evt_test->assert_empty_param(4);
		evt_test->assert_num_params_pushed(5);
		GTEST_SKIP() << "[RECVMSG_X]: we receive an empty tuple but we have all the data in the kernel to obtain the correct tuple" << std::endl;
	}

	/* Parameter 5: msg_control (type: PT_BYTEBUF) */
	evt_test->assert_empty_param(5);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

TEST(SyscallExit, recvmsgX_tcp_connection_NULL_sockaddr)
{
	auto evt_test = get_syscall_event_test(__NR_recvmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_socket_fd = 0;
	int32_t server_socket_fd = 0;
	sockaddr_in client_addr = {};
	sockaddr_in server_addr = {};
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
	recv_msg.msg_name = NULL;
	recv_msg.msg_namelen = 0;
	char data_1[MAX_RECV_BUF_SIZE];
	char data_2[MAX_RECV_BUF_SIZE];
	iov[0].iov_base = data_1;
	iov[0].iov_len = MAX_RECV_BUF_SIZE;
	iov[1].iov_base = data_2;
	iov[1].iov_len = MAX_RECV_BUF_SIZE;
	recv_msg.msg_iov = iov;
	recv_msg.msg_iovlen = 2;
	uint32_t recvmsg_flags = 0;

	int64_t received_bytes = syscall(__NR_recvmsg, connected_socket_fd, &recv_msg, recvmsg_flags);
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
		evt_test->assert_empty_param(4);
		evt_test->assert_num_params_pushed(5);
		GTEST_SKIP() << "[RECVMSG_X]: we receive an empty tuple because the pointer to sockaddr is NULL, but we should rely on kernel structs" << std::endl;
	}

	/* Parameter 5: msg_control (type: PT_BYTEBUF) */
	evt_test->assert_empty_param(5);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

TEST(SyscallExit, recvmsgX_udp_connection_snaplen)
{
	auto evt_test = get_syscall_event_test(__NR_recvmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_socket_fd = 0;
	int32_t server_socket_fd = 0;
	sockaddr_in client_addr = {};
	sockaddr_in server_addr = {};
	evt_test->connect_ipv4_udp_client_to_server(&client_socket_fd, &client_addr, &server_socket_fd, &server_addr);

	/* Send a message to the server */
	char sent_data[FULL_MESSAGE_LEN] = FULL_MESSAGE;
	uint32_t sendto_flags = 0;
	int64_t sent_bytes = syscall(__NR_sendto, client_socket_fd, sent_data, sizeof(sent_data), sendto_flags, (sockaddr*)&server_addr, sizeof(server_addr));
	assert_syscall_state(SYSCALL_SUCCESS, "sendto (client)", sent_bytes, NOT_EQUAL, -1);

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

	int64_t received_bytes = syscall(__NR_recvmsg, server_socket_fd, &recv_msg, recvmsg_flags);
	assert_syscall_state(SYSCALL_SUCCESS, "recvmsg (server)", received_bytes, NOT_EQUAL, -1);

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
	evt_test->assert_numeric_param(1, (int64_t)FULL_MESSAGE_LEN);

	/* Parameter 2: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (uint32_t)FULL_MESSAGE_LEN);

	/* Parameter 3: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(3, FULL_MESSAGE, DEFAULT_SNAPLEN);

	/* Parameter 4: tuple (type: PT_SOCKTUPLE) */
	if(evt_test->is_modern_bpf_engine())
	{
		/* we are not able to get the sorce ip + port because right now
		 * we don't use the userspace struct.
		 */
		evt_test->assert_tuple_inet_param(4, PPM_AF_INET, IPV4_EMPTY, IPV4_SERVER, IPV4_PORT_EMPTY_STRING, IPV4_PORT_SERVER_STRING);
		evt_test->assert_num_params_pushed(5);
		GTEST_SKIP() << "[RECVMSG_X]: we are not able to get the sorce ip + port because right now we don't use the userspace struct." << std::endl;
	}
	else
	{
		evt_test->assert_tuple_inet_param(4, PPM_AF_INET, IPV4_CLIENT, IPV4_SERVER, IPV4_PORT_CLIENT_STRING, IPV4_PORT_SERVER_STRING);
	}

	/* Parameter 5: msg_control (type: PT_BYTEBUF) */
	evt_test->assert_empty_param(5);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

TEST(SyscallExit, recvmsgX_udp_connection_NULL_sockaddr)
{
	auto evt_test = get_syscall_event_test(__NR_recvmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_socket_fd = 0;
	int32_t server_socket_fd = 0;
	sockaddr_in client_addr = {};
	sockaddr_in server_addr = {};
	evt_test->connect_ipv4_udp_client_to_server(&client_socket_fd, &client_addr, &server_socket_fd, &server_addr);

	/* Send a message to the server */
	char sent_data[FULL_MESSAGE_LEN] = FULL_MESSAGE;
	uint32_t sendto_flags = 0;
	int64_t sent_bytes = syscall(__NR_sendto, client_socket_fd, sent_data, sizeof(sent_data), sendto_flags, (sockaddr*)&server_addr, sizeof(server_addr));
	assert_syscall_state(SYSCALL_SUCCESS, "sendto (client)", sent_bytes, NOT_EQUAL, -1);

	struct msghdr recv_msg;
	struct iovec iov[2];
	memset(&recv_msg, 0, sizeof(recv_msg));
	memset(iov, 0, sizeof(iov));
	recv_msg.msg_name = NULL;
	recv_msg.msg_namelen = 0;
	char data_1[MAX_RECV_BUF_SIZE];
	char data_2[MAX_RECV_BUF_SIZE];
	iov[0].iov_base = data_1;
	iov[0].iov_len = MAX_RECV_BUF_SIZE;
	iov[1].iov_base = data_2;
	iov[1].iov_len = MAX_RECV_BUF_SIZE;
	recv_msg.msg_iov = iov;
	recv_msg.msg_iovlen = 2;
	uint32_t recvmsg_flags = 0;

	int64_t received_bytes = syscall(__NR_recvmsg, server_socket_fd, &recv_msg, recvmsg_flags);
	assert_syscall_state(SYSCALL_SUCCESS, "recvmsg (server)", received_bytes, NOT_EQUAL, -1);

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
	evt_test->assert_numeric_param(1, (int64_t)FULL_MESSAGE_LEN);

	/* Parameter 2: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (uint32_t)FULL_MESSAGE_LEN);

	/* Parameter 3: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(3, FULL_MESSAGE, DEFAULT_SNAPLEN);

	/* Parameter 4: tuple (type: PT_SOCKTUPLE) */
	if(evt_test->is_modern_bpf_engine())
	{
		/* This is the correct behavior because if the userspace struct is empty
		 * we cannot extract the source ip and port, unless we directly read the packet
		 * headers!
		 */
		evt_test->assert_tuple_inet_param(4, PPM_AF_INET, IPV4_EMPTY, IPV4_SERVER, IPV4_PORT_EMPTY_STRING, IPV4_PORT_SERVER_STRING);
	}
	else
	{
		evt_test->assert_empty_param(4);
		GTEST_SKIP() << "[RECVMSG_X]: we send an empty tuple, but we can at least send the dest ip and source" << std::endl;
	}

	/* Parameter 5: msg_control (type: PT_BYTEBUF) */
	evt_test->assert_empty_param(5);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}
#endif

TEST(SyscallExit, recvmsgX_fail)
{
	auto evt_test = get_syscall_event_test(__NR_recvmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t mock_fd = -1;
	struct msghdr *msg = NULL;
	int flags = 0;
	assert_syscall_state(SYSCALL_FAILURE, "recvmsg", syscall(__NR_recvmsg, mock_fd, msg, flags));
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
}

TEST(SyscallExit, recvmsg_ancillary_data)
{
	auto evt_test = get_syscall_event_test(__NR_recvmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_socket_fd = 0;
	int32_t server_socket_fd = 0;
	struct sockaddr_un client_addr = {};
	struct sockaddr_un server_addr = {};
	evt_test->connect_unix_client_to_server(&client_socket_fd, &client_addr, &server_socket_fd, &server_addr);
	int64_t received_bytes, sent_bytes, msg_controllen;
	struct cmsghdr *cmsg;
	char cmsg_buf[CMSG_SPACE(sizeof(int))];
	struct iovec iov = {
		.iov_base = (void *)FULL_MESSAGE,
		.iov_len = FULL_MESSAGE_LEN,
	};

	/* We don't want to get any info about the connected socket so `addr` and `addrlen` are NULL. */
	int connected_socket_fd = syscall(__NR_accept4, server_socket_fd, NULL, NULL, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "accept (server)", connected_socket_fd, NOT_EQUAL, -1);

	/* Now we can fork. We still maintain the connected_socket_fd in both parent and child processes */
	pid_t pid = fork();
	if(pid)
	{
		/* Create a socket. It is used to pass it to the child process, just for test purposes */
		int sock = socket(AF_UNIX, SOCK_STREAM, 0);
		msghdr msg = {};
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = cmsg_buf;
		msg.msg_controllen = sizeof(cmsg_buf);

		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(sock));

		memcpy(CMSG_DATA(cmsg), &sock, sizeof(sock));

		sent_bytes = syscall(__NR_sendmsg, client_socket_fd, &msg, 0);
		assert_syscall_state(SYSCALL_SUCCESS, "sendmsg (client)", sent_bytes, NOT_EQUAL, -1);;

		int wstatus;
		waitpid(pid, &wstatus, 0);

		syscall(__NR_shutdown, sock);
		syscall(__NR_close, sock);
	} else
	{
		char buf[FULL_MESSAGE_LEN];
		iov = {
			iov.iov_base = (void *)buf,
			iov.iov_len = sizeof(buf)
		};

		msghdr msg = {};
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = cmsg_buf;
		msg.msg_controllen = sizeof(cmsg_buf);

		iov.iov_base = (void *)buf;
		iov.iov_len = sizeof(buf);

		received_bytes = syscall(__NR_recvmsg, connected_socket_fd, &msg, 0);
		assert_syscall_state(SYSCALL_SUCCESS, "recvmsg (server)", received_bytes, NOT_EQUAL, -1);
		exit(0);
	}

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

	evt_test->assert_event_presence(pid);

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

	/* Parameter 5: msg_control (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(5, (const char *)cmsg, msg_controllen);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

#endif

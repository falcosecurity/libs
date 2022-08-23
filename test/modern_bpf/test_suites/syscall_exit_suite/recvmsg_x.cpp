#include "../../event_class/event_class.h"

#ifdef __NR_recvmsg

#if defined(__NR_connect) && defined(__NR_socket) && defined(__NR_bind) && defined(__NR_listen) && defined(__NR_close) && defined(__NR_setsockopt) && defined(__NR_shutdown) && defined(__NR_sendto)

TEST(SyscallExit, recvmsgX_no_snaplen)
{
	auto evt_test = new event_test(__NR_recvmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Create the server socket. */
	int32_t server_socket_fd = syscall(__NR_socket, AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "socket (server)", server_socket_fd, NOT_EQUAL, -1);
	evt_test->server_reuse_address_port(server_socket_fd);

	struct sockaddr_in server_addr;
	evt_test->server_fill_sockaddr_in(&server_addr);

	/* Now we bind the server socket with the server address. */
	assert_syscall_state(SYSCALL_SUCCESS, "bind (server)", syscall(__NR_bind, server_socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)), NOT_EQUAL, -1);
	assert_syscall_state(SYSCALL_SUCCESS, "listen (server)", syscall(__NR_listen, server_socket_fd, QUEUE_LENGTH), NOT_EQUAL, -1);

	/* The server now is ready, we need to create at least one connection from the client. */

	int32_t client_socket_fd = syscall(__NR_socket, AF_INET, SOCK_STREAM, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "socket (client)", client_socket_fd, NOT_EQUAL, -1);
	evt_test->client_reuse_address_port(client_socket_fd);

	struct sockaddr_in client_addr;
	evt_test->client_fill_sockaddr_in(&client_addr);

	/* We need to bind the client socket with an address otherwise we cannot assert against it. */
	assert_syscall_state(SYSCALL_SUCCESS, "bind (client)", syscall(__NR_bind, client_socket_fd, (struct sockaddr *)&client_addr, sizeof(client_addr)), NOT_EQUAL, -1);
	assert_syscall_state(SYSCALL_SUCCESS, "connect (client)", syscall(__NR_connect, client_socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)), NOT_EQUAL, -1);

	/* Send a message to the server */
	char sent_data[SENDMSG_NO_SNAPLEN_LEN] = SENDMSG_NO_SNAPLEN_MESSAGE;
	uint32_t sendto_flags = 0;
	int64_t sent_bytes = syscall(__NR_sendto, client_socket_fd, sent_data, sizeof(sent_data), sendto_flags, (struct sockaddr *)&server_addr, sizeof(server_addr));
	assert_syscall_state(SYSCALL_SUCCESS, "sendto (client)", sent_bytes, NOT_EQUAL, -1);

	/* The server accepts the connection and receives the message */
	int connected_socket_fd = syscall(__NR_accept, server_socket_fd, NULL, NULL);
	assert_syscall_state(SYSCALL_SUCCESS, "accept (server)", connected_socket_fd, NOT_EQUAL, -1);

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
	evt_test->assert_bytebuf_param(3, SENDMSG_NO_SNAPLEN_MESSAGE, sent_bytes);

	/* Parameter 4: tuple (type: PT_SOCKTUPLE) */
	/* The server performs a 'recvmsg` so the server is the final destination of the packet while the client is the src. */
	evt_test->assert_tuple_inet_param(4, PPM_AF_INET, IPV4_CLIENT, IPV4_SERVER, IPV4_PORT_CLIENT_STRING, IPV4_PORT_SERVER_STRING);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);
}

TEST(SyscallExit, recvmsgX_snaplen)
{
	auto evt_test = new event_test(__NR_recvmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Create the server socket. */
	int32_t server_socket_fd = syscall(__NR_socket, AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "socket (server)", server_socket_fd, NOT_EQUAL, -1);
	evt_test->server_reuse_address_port(server_socket_fd);

	struct sockaddr_in server_addr;
	evt_test->server_fill_sockaddr_in(&server_addr);

	/* Now we bind the server socket with the server address. */
	assert_syscall_state(SYSCALL_SUCCESS, "bind (server)", syscall(__NR_bind, server_socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)), NOT_EQUAL, -1);
	assert_syscall_state(SYSCALL_SUCCESS, "listen (server)", syscall(__NR_listen, server_socket_fd, QUEUE_LENGTH), NOT_EQUAL, -1);

	/* The server now is ready, we need to create at least one connection from the client. */

	int32_t client_socket_fd = syscall(__NR_socket, AF_INET, SOCK_STREAM, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "socket (client)", client_socket_fd, NOT_EQUAL, -1);
	evt_test->client_reuse_address_port(client_socket_fd);

	struct sockaddr_in client_addr;
	evt_test->client_fill_sockaddr_in(&client_addr);

	/* We need to bind the client socket with an address otherwise we cannot assert against it. */
	assert_syscall_state(SYSCALL_SUCCESS, "bind (client)", syscall(__NR_bind, client_socket_fd, (struct sockaddr *)&client_addr, sizeof(client_addr)), NOT_EQUAL, -1);
	assert_syscall_state(SYSCALL_SUCCESS, "connect (client)", syscall(__NR_connect, client_socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)), NOT_EQUAL, -1);

	/* Send a message to the server */
	char sent_data[SENDMSG_FULL_LEN] = SENDMSG_FULL_MESSAGE;
	uint32_t sendto_flags = 0;
	int64_t sent_bytes = syscall(__NR_sendto, client_socket_fd, sent_data, sizeof(sent_data), sendto_flags, (struct sockaddr *)&server_addr, sizeof(server_addr));
	assert_syscall_state(SYSCALL_SUCCESS, "sendto (client)", sent_bytes, NOT_EQUAL, -1);

	/* The server accepts the connection and receives the message */
	int connected_socket_fd = syscall(__NR_accept, server_socket_fd, NULL, NULL);
	assert_syscall_state(SYSCALL_SUCCESS, "accept (server)", connected_socket_fd, NOT_EQUAL, -1);

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
	evt_test->assert_numeric_param(1, (int64_t)SENDMSG_FULL_LEN);

	/* Parameter 2: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (uint32_t)SENDMSG_FULL_LEN);

	/* Parameter 3: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(3, SENDMSG_FULL_MESSAGE, DEFAULT_SNAPLEN);

	/* Parameter 4: tuple (type: PT_SOCKTUPLE) */
	/* The server performs a 'recvmsg` so the server is the final destination of the packet while the client is the src. */
	evt_test->assert_tuple_inet_param(4, PPM_AF_INET, IPV4_CLIENT, IPV4_SERVER, IPV4_PORT_CLIENT_STRING, IPV4_PORT_SERVER_STRING);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);
}
#endif

TEST(SyscallExit, recvmsgX_fail)
{
	auto evt_test = new event_test(__NR_recvmsg, EXIT_EVENT);

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

	/*=============================== ASSERT PARAMETERS  ===========================*/
}

#endif

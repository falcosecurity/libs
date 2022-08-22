#include "../../event_class/event_class.h"

#ifdef __NR_sendmsg

#if defined(__NR_connect) && defined(__NR_socket) && defined(__NR_bind) && defined(__NR_listen) && defined(__NR_close) && defined(__NR_setsockopt) && defined(__NR_shutdown)

/* By default `snaplen` is 80 bytes.
 * No `snaplen` because here we don't hit the 80 bytes so we don't have to truncate the message.
 */
TEST(SyscallExit, sendmsgX_no_snaplen)
{
	auto evt_test = new event_test(__NR_sendmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Create the server socket. */
	int32_t server_socket_fd = syscall(__NR_socket, AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "socket (server)", server_socket_fd, NOT_EQUAL, -1);
	evt_test->server_reuse_address_port(server_socket_fd);

	struct sockaddr_in server_addr;
	evt_test->server_fill_sockaddr_in(&server_addr);

	/* Now we bind the server socket with the server address. */
	assert_syscall_state(SYSCALL_SUCCESS, "bind (server)", syscall(__NR_bind, server_socket_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)), NOT_EQUAL, -1);
	assert_syscall_state(SYSCALL_SUCCESS, "listen (server)", syscall(__NR_listen, server_socket_fd, QUEUE_LENGTH), NOT_EQUAL, -1);

	/* The server now is ready, we need to create at least one connection from the client. */

	int32_t client_socket_fd = syscall(__NR_socket, AF_INET, SOCK_STREAM, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "socket (client)", client_socket_fd, NOT_EQUAL, -1);
	evt_test->client_reuse_address_port(client_socket_fd);

	struct sockaddr_in client_addr;
	evt_test->client_fill_sockaddr_in(&client_addr);

	/* We need to bind the client socket with an address otherwise we cannot assert against it. */
	assert_syscall_state(SYSCALL_SUCCESS, "bind (client)", syscall(__NR_bind, client_socket_fd, (struct sockaddr*)&client_addr, sizeof(client_addr)), NOT_EQUAL, -1);
	assert_syscall_state(SYSCALL_SUCCESS, "connect (client)", syscall(__NR_connect, client_socket_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)), NOT_EQUAL, -1);

	/* Send a message to the server */
	struct msghdr send_msg;
	struct iovec iov[2];
	memset(&send_msg, 0, sizeof(send_msg));
	memset(iov, 0, sizeof(iov));
	send_msg.msg_name = (struct sockaddr*)&server_addr;
	send_msg.msg_namelen = sizeof(server_addr);
	char sent_data_1[SENDMSG_FIRST_LEN] = "hey! there is a first message here.";
	char sent_data_2[SENDMSG_SECOND_LEN] = "hey! there is a second message here.";
	iov[0].iov_base = sent_data_1;
	iov[0].iov_len = sizeof(sent_data_1);
	iov[1].iov_base = sent_data_2;
	iov[1].iov_len = sizeof(sent_data_2);
	send_msg.msg_iov = iov;
	send_msg.msg_iovlen = 2;
	uint32_t sendmsg_flags = 0;

	int64_t sent_bytes = syscall(__NR_sendmsg, client_socket_fd, &send_msg, sendmsg_flags);
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
	evt_test->assert_bytebuf_param(2, SENDMSG_NO_SNAPLEN_MESSAGE, sent_bytes);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

/* Here we need to truncate our message since it is greater than `snaplen` */
TEST(SyscallExit, sendmsgX_snaplen)
{
	auto evt_test = new event_test(__NR_sendmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Create the server socket. */
	int32_t server_socket_fd = syscall(__NR_socket, AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "socket (server)", server_socket_fd, NOT_EQUAL, -1);
	evt_test->server_reuse_address_port(server_socket_fd);

	struct sockaddr_in server_addr;
	evt_test->server_fill_sockaddr_in(&server_addr);

	/* Now we bind the server socket with the server address. */
	assert_syscall_state(SYSCALL_SUCCESS, "bind (server)", syscall(__NR_bind, server_socket_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)), NOT_EQUAL, -1);
	assert_syscall_state(SYSCALL_SUCCESS, "listen (server)", syscall(__NR_listen, server_socket_fd, QUEUE_LENGTH), NOT_EQUAL, -1);

	/* The server now is ready, we need to create at least one connection from the client. */

	int32_t client_socket_fd = syscall(__NR_socket, AF_INET, SOCK_STREAM, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "socket (client)", client_socket_fd, NOT_EQUAL, -1);
	evt_test->client_reuse_address_port(client_socket_fd);

	struct sockaddr_in client_addr;
	evt_test->client_fill_sockaddr_in(&client_addr);

	/* We need to bind the client socket with an address otherwise we cannot assert against it. */
	assert_syscall_state(SYSCALL_SUCCESS, "bind (client)", syscall(__NR_bind, client_socket_fd, (struct sockaddr*)&client_addr, sizeof(client_addr)), NOT_EQUAL, -1);
	assert_syscall_state(SYSCALL_SUCCESS, "connect (client)", syscall(__NR_connect, client_socket_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)), NOT_EQUAL, -1);

	/* Send a message to the server */
	struct msghdr send_msg;
	struct iovec iov[3];
	memset(&send_msg, 0, sizeof(send_msg));
	memset(iov, 0, sizeof(iov));
	send_msg.msg_name = (struct sockaddr*)&server_addr;
	send_msg.msg_namelen = sizeof(server_addr);
	char sent_data_1[SENDMSG_FIRST_LEN] = "hey! there is a first message here.";
	char sent_data_2[SENDMSG_SECOND_LEN] = "hey! there is a second message here.";
	char sent_data_3[SENDMSG_THIRD_LEN] = "hey! there is a third message here.";
	iov[0].iov_base = sent_data_1;
	iov[0].iov_len = sizeof(sent_data_1);
	iov[1].iov_base = sent_data_2;
	iov[1].iov_len = sizeof(sent_data_2);
	iov[2].iov_base = sent_data_3;
	iov[2].iov_len = sizeof(sent_data_3);
	send_msg.msg_iov = iov;
	send_msg.msg_iovlen = 3;
	uint32_t sendmsg_flags = 0;

	int64_t sent_bytes = syscall(__NR_sendmsg, client_socket_fd, &send_msg, sendmsg_flags);
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
	evt_test->assert_bytebuf_param(2, SENDMSG_FULL_MESSAGE, DEFAULT_SNAPLEN);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}
#endif

TEST(SyscallExit, sendmsgX_fail)
{
	auto evt_test = new event_test(__NR_sendmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t mock_fd = -1;
	struct msghdr* send_msg = NULL;
	uint32_t sendmsg_flags = 0;

	assert_syscall_state(SYSCALL_FAILURE, "sendmsg", syscall(__NR_sendmsg, mock_fd, send_msg, sendmsg_flags));
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
}

#endif /* __NR_sendmsg */

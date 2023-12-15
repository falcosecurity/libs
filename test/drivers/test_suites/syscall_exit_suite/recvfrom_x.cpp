#include "../../event_class/event_class.h"

#ifdef __NR_recvfrom

#if defined(__NR_accept4) && defined(__NR_connect) && defined(__NR_socket) && defined(__NR_bind) && defined(__NR_listen) && defined(__NR_close) && defined(__NR_setsockopt) && defined(__NR_shutdown) && defined(__NR_sendto)

TEST(SyscallExit, recvfromX_tcp_connection_no_snaplen)
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
	sockaddr_in src_addr = {0};
	socklen_t addrlen = sizeof(src_addr);

	int64_t received_bytes = syscall(__NR_recvfrom, connected_socket_fd, received_data, received_data_len, recvfrom_flags, (sockaddr*)&src_addr, &addrlen);
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

TEST(SyscallExit, recvfromX_tcp_connection_snaplen)
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

	int64_t received_bytes = syscall(__NR_recvfrom, connected_socket_fd, received_data, received_data_len, recvfrom_flags, (sockaddr*)&src_addr, &addrlen);
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

TEST(SyscallExit, recvfromX_tcp_connection_NULL_sockaddr)
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

	/// TODO: if we use `sockaddr_in* src_addr = NULL` kernel module and old bpf are not able to get correct data.
	/// There is a check on the sockaddr pointer if it is NULL we return an empty tuple. We need to fix it.
	int64_t received_bytes = syscall(__NR_recvfrom, connected_socket_fd, received_data, received_data_len, recvfrom_flags, NULL, 0);
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
	if(evt_test->is_modern_bpf_engine())
	{
		/* The server performs a 'recvmsg` so the server is the final destination of the packet while the client is the src. */
		evt_test->assert_tuple_inet_param(3, PPM_AF_INET, IPV4_CLIENT, IPV4_SERVER, IPV4_PORT_CLIENT_STRING, IPV4_PORT_SERVER_STRING);
	}
	else
	{
		evt_test->assert_empty_param(3);
		evt_test->assert_num_params_pushed(3);
		GTEST_SKIP() << "[RECVFROM_X]: we send an empty tuple, but we can fix this case" << std::endl;
	}

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}

TEST(SyscallExit, recvfromX_udp_connection_snaplen)
{
	auto evt_test = get_syscall_event_test(__NR_recvfrom, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_socket_fd = 0;
	int32_t server_socket_fd = 0;
	sockaddr_in client_addr = {0};
	sockaddr_in server_addr = {0};
	evt_test->connect_ipv4_udp_client_to_server(&client_socket_fd, &client_addr, &server_socket_fd, &server_addr);

	/* Send a message to the server */
	char sent_data[FULL_MESSAGE_LEN] = FULL_MESSAGE;
	uint32_t sendto_flags = 0;
	int64_t sent_bytes = syscall(__NR_sendto, client_socket_fd, sent_data, sizeof(sent_data), sendto_flags,
				     (sockaddr*)&server_addr, sizeof(server_addr));
	assert_syscall_state(SYSCALL_SUCCESS, "sendto (client)", sent_bytes, NOT_EQUAL, -1);

	char received_data[MAX_RECV_BUF_SIZE];
	socklen_t received_data_len = MAX_RECV_BUF_SIZE;
	uint32_t recvfrom_flags = 0;
	sockaddr_in src_addr = {0};
	socklen_t addrlen = sizeof(src_addr);

	int64_t received_bytes = syscall(__NR_recvfrom, server_socket_fd, received_data, received_data_len,
					 recvfrom_flags, (sockaddr*)&src_addr, &addrlen);
	assert_syscall_state(SYSCALL_SUCCESS, "recvfrom (server)", received_bytes, NOT_EQUAL, -1);

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
	evt_test->assert_numeric_param(1, (int64_t)MAX_RECV_BUF_SIZE);

	/* Parameter 2: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(2, FULL_MESSAGE, DEFAULT_SNAPLEN);

	/* Parameter 3: tuple (type: PT_SOCKTUPLE) */
	if(!evt_test->is_modern_bpf_engine())
	{
		/* The server performs a 'recvmsg` so the server is the final destination of the packet while the client is the src. */
		evt_test->assert_tuple_inet_param(3, PPM_AF_INET, IPV4_CLIENT, IPV4_SERVER, IPV4_PORT_CLIENT_STRING, IPV4_PORT_SERVER_STRING);
	}
	else
	{
		/* In UDP connections we cannot extract the tuple from kernel structs we always need to use the userspace struct
		 * Right now the modern probe doesn't support this behavior we need to fix it
		 */
		evt_test->assert_tuple_inet_param(3, PPM_AF_INET, IPV4_EMPTY, IPV4_SERVER, IPV4_PORT_EMPTY_STRING, IPV4_PORT_SERVER_STRING);
		evt_test->assert_num_params_pushed(3);
		GTEST_SKIP() << "[RECVFROM_X]: we send a tuple without the source, but we can fix this case" << std::endl;
	}

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}

TEST(SyscallExit, recvfromX_udp_connection_NULL_sockaddr)
{
	auto evt_test = get_syscall_event_test(__NR_recvfrom, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_socket_fd = 0;
	int32_t server_socket_fd = 0;
	sockaddr_in client_addr = {0};
	sockaddr_in server_addr = {0};
	evt_test->connect_ipv4_udp_client_to_server(&client_socket_fd, &client_addr, &server_socket_fd, &server_addr);

	/* Send a message to the server */
	char sent_data[FULL_MESSAGE_LEN] = FULL_MESSAGE;
	uint32_t sendto_flags = 0;
	int64_t sent_bytes = syscall(__NR_sendto, client_socket_fd, sent_data, sizeof(sent_data), sendto_flags,
				     (sockaddr*)&server_addr, sizeof(server_addr));
	assert_syscall_state(SYSCALL_SUCCESS, "sendto (client)", sent_bytes, NOT_EQUAL, -1);

	char received_data[MAX_RECV_BUF_SIZE];
	socklen_t received_data_len = MAX_RECV_BUF_SIZE;
	uint32_t recvfrom_flags = 0;

	int64_t received_bytes = syscall(__NR_recvfrom, server_socket_fd, received_data, received_data_len,
					 recvfrom_flags, NULL, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "recvfrom (server)", received_bytes, NOT_EQUAL, -1);

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
	evt_test->assert_numeric_param(1, (int64_t)MAX_RECV_BUF_SIZE);

	/* Parameter 2: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(2, FULL_MESSAGE, DEFAULT_SNAPLEN);

	/* Parameter 3: tuple (type: PT_SOCKTUPLE) */
	if(!evt_test->is_modern_bpf_engine())
	{
		evt_test->assert_empty_param(3);
		GTEST_SKIP() << "[RECVFROM_X]: we send an empty tuple, but we can at least send the dest ip and source" << std::endl;
	}
	else
	{
		/* This is the correct behavior because if the userspace struct is empty
		 * we cannot extract the source ip and port, unless we directly read the packet
		 * headers!
		 */
		evt_test->assert_tuple_inet_param(3, PPM_AF_INET, IPV4_EMPTY, IPV4_SERVER, IPV4_PORT_EMPTY_STRING, IPV4_PORT_SERVER_STRING);
	}

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}
#endif

TEST(SyscallExit, recvfromX_fail)
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
	assert_syscall_state(SYSCALL_FAILURE, "recvfrom", syscall(__NR_recvfrom, mock_fd, received_data, received_data_len, flags, src_addr, addrlen));
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

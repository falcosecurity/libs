#include "../../event_class/event_class.h"

#ifdef __NR_recvmmsg

#if defined(__NR_accept4) && defined(__NR_connect) && defined(__NR_socket) &&         \
        defined(__NR_bind) && defined(__NR_listen) && defined(__NR_close) &&          \
        defined(__NR_setsockopt) && defined(__NR_shutdown) && defined(__NR_sendto) && \
        defined(__NR_sendmsg)

TEST(SyscallExit, recvmmsgX_ipv4_tcp_no_snaplen) {
	auto evt_test = get_syscall_event_test(__NR_recvmmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_fd, server_fd;
	evt_test->client_to_server_ipv4_tcp(&client_fd,
	                                    &server_fd,
	                                    send_data{
	                                            .syscall_num = __NR_sendto,
	                                    },
	                                    recv_data{
	                                            .syscall_num = __NR_recvmmsg,
	                                    });

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure()) {
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)SHORT_MESSAGE_LEN);

	/* Parameter 2: fd (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (int64_t)server_fd);

	/* Parameter 3: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(3, (uint32_t)SHORT_MESSAGE_LEN);

	/* Parameter 4: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(4, SHORT_MESSAGE, SHORT_MESSAGE_LEN);

	/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
	if(evt_test->is_modern_bpf_engine()) {
		/* The server performs a 'recvmmsg` so the server is the final destination of the packet
		 * while the client is the src. */
		evt_test->assert_tuple_inet_param(5,
		                                  PPM_AF_INET,
		                                  IPV4_CLIENT,
		                                  IPV4_SERVER,
		                                  IPV4_PORT_CLIENT_STRING,
		                                  IPV4_PORT_SERVER_STRING);
	} else {
		/// TODO: If the socket is connected, the msg_name and msg_namelen members shall be ignored,
		/// but right now we use them to send data also in TCP connections so we need to change this
		/// behavior!
		evt_test->assert_empty_param(5);
		evt_test->assert_num_params_pushed(6);
		GTEST_SKIP() << "[RECVMMSG_X]: we receive an empty tuple but we have all the data in the "
		                "kernel to "
		                "obtain the correct tuple"
		             << std::endl;
	}

	/* Parameter 6: msg_control (type: PT_BYTEBUF) */
	evt_test->assert_empty_param(6);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(6);
}

TEST(SyscallExit, recvmmsgX_ipv4_tcp_truncated) {
	auto evt_test = get_syscall_event_test(__NR_recvmmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_fd, server_fd;
	evt_test->client_to_server_ipv4_tcp(&client_fd,
	                                    &server_fd,
	                                    send_data{
	                                            .syscall_num = __NR_sendto,
	                                            .greater_snaplen = true,
	                                    },
	                                    recv_data{
	                                            .syscall_num = __NR_recvmmsg,
	                                    });

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure()) {
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)MAX_RECV_BUF_SIZE);

	/* Parameter 2: fd (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (int64_t)server_fd);

	/* Parameter 3: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(3, (uint32_t)MAX_RECV_BUF_SIZE);

	/* Parameter 4: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(4, LONG_MESSAGE, DEFAULT_SNAPLEN);

	if(evt_test->is_modern_bpf_engine()) {
		/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
		/* The server performs a 'recvmsg` so the server is the final destination of the packet
		 * while the client is the src. */
		evt_test->assert_tuple_inet_param(5,
		                                  PPM_AF_INET,
		                                  IPV4_CLIENT,
		                                  IPV4_SERVER,
		                                  IPV4_PORT_CLIENT_STRING,
		                                  IPV4_PORT_SERVER_STRING);
	} else {
		evt_test->assert_empty_param(5);
		evt_test->assert_num_params_pushed(6);
		GTEST_SKIP() << "[RECVMSG_X]: we receive an empty tuple but we have all the data in the "
		                "kernel to obtain the correct tuple"
		             << std::endl;
	}

	/* Parameter 5: msg_control (type: PT_BYTEBUF) */
	evt_test->assert_empty_param(6);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(6);
}

TEST(SyscallExit, recvmmsgX_ipv6_tcp_no_snaplen) {
	auto evt_test = get_syscall_event_test(__NR_recvmmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_fd, server_fd;
	evt_test->client_to_server_ipv6_tcp(&client_fd,
	                                    &server_fd,
	                                    send_data{
	                                            .syscall_num = __NR_sendto,
	                                    },
	                                    recv_data{
	                                            .syscall_num = __NR_recvmmsg,
	                                    });

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure()) {
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)SHORT_MESSAGE_LEN);

	/* Parameter 2: fd (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (int64_t)server_fd);

	/* Parameter 3: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(3, (uint32_t)SHORT_MESSAGE_LEN);

	/* Parameter 4: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(4, SHORT_MESSAGE, SHORT_MESSAGE_LEN);

	/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
	if(evt_test->is_modern_bpf_engine()) {
		/* The server performs a 'recvmmsg` so the server is the final destination of the packet
		 * while the client is the src. */
		evt_test->assert_tuple_inet6_param(5,
		                                   PPM_AF_INET6,
		                                   IPV6_CLIENT,
		                                   IPV6_SERVER,
		                                   IPV6_PORT_CLIENT_STRING,
		                                   IPV6_PORT_SERVER_STRING);
	} else {
		/// TODO: If the socket is connected, the msg_name and msg_namelen members shall be ignored,
		/// but right now we use them to send data also in TCP connections so we need to change this
		/// behavior!
		evt_test->assert_empty_param(5);
		evt_test->assert_num_params_pushed(6);
		GTEST_SKIP() << "[RECVMMSG_X]: we receive an empty tuple but we have all the data in the "
		                "kernel to "
		                "obtain the correct tuple"
		             << std::endl;
	}

	/* Parameter 6: msg_control (type: PT_BYTEBUF) */
	evt_test->assert_empty_param(6);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(6);
}

TEST(SyscallExit, recvmmsgX_ipv6_tcp_truncated) {
	auto evt_test = get_syscall_event_test(__NR_recvmmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/
	int32_t client_fd, server_fd;
	evt_test->client_to_server_ipv6_tcp(&client_fd,
	                                    &server_fd,
	                                    send_data{
	                                            .syscall_num = __NR_sendto,
	                                            .greater_snaplen = true,
	                                    },
	                                    recv_data{
	                                            .syscall_num = __NR_recvmmsg,
	                                    });

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure()) {
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)MAX_RECV_BUF_SIZE);

	/* Parameter 2: fd (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (int64_t)server_fd);

	/* Parameter 3: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(3, (uint32_t)MAX_RECV_BUF_SIZE);

	/* Parameter 4: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(4, LONG_MESSAGE, DEFAULT_SNAPLEN);

	if(evt_test->is_modern_bpf_engine()) {
		/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
		/* The server performs a 'recvmsg` so the server is the final destination of the packet
		 * while the client is the src. */
		evt_test->assert_tuple_inet6_param(5,
		                                   PPM_AF_INET6,
		                                   IPV6_CLIENT,
		                                   IPV6_SERVER,
		                                   IPV6_PORT_CLIENT_STRING,
		                                   IPV6_PORT_SERVER_STRING);
	} else {
		evt_test->assert_empty_param(5);
		evt_test->assert_num_params_pushed(6);
		GTEST_SKIP() << "[RECVMSG_X]: we receive an empty tuple but we have all the data in the "
		                "kernel to obtain the correct tuple"
		             << std::endl;
	}

	/* Parameter 5: msg_control (type: PT_BYTEBUF) */
	evt_test->assert_empty_param(6);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(6);
}
TEST(SyscallExit, recvmmsgX_ipv4_udp_no_snaplen) {
	auto evt_test = get_syscall_event_test(__NR_recvmmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/
	int32_t client_fd, server_fd;
	evt_test->client_to_server_ipv4_udp(&client_fd,
	                                    &server_fd,
	                                    send_data{
	                                            .syscall_num = __NR_sendto,
	                                    },
	                                    recv_data{
	                                            .syscall_num = __NR_recvmmsg,
	                                    });

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure()) {
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)SHORT_MESSAGE_LEN);

	/* Parameter 2: fd (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (int64_t)server_fd);

	/* Parameter 3: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(3, (uint32_t)SHORT_MESSAGE_LEN);

	/* Parameter 4: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(4, SHORT_MESSAGE, SHORT_MESSAGE_LEN);

	/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
	/* The server performs a 'recvmmsg` so the server is the final destination of the packet
	 * while the client is the src. */
	evt_test->assert_tuple_inet_param(5,
	                                  PPM_AF_INET,
	                                  IPV4_CLIENT,
	                                  IPV4_SERVER,
	                                  IPV4_PORT_CLIENT_STRING,
	                                  IPV4_PORT_SERVER_STRING);

	/* Parameter 6: msg_control (type: PT_BYTEBUF) */
	evt_test->assert_empty_param(6);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(6);
}

TEST(SyscallExit, recvmmsgX_ipv4_udp_truncated) {
	auto evt_test = get_syscall_event_test(__NR_recvmmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_fd, server_fd;
	evt_test->client_to_server_ipv4_udp(&client_fd,
	                                    &server_fd,
	                                    send_data{
	                                            .syscall_num = __NR_sendto,
	                                            .greater_snaplen = true,
	                                    },
	                                    recv_data{
	                                            .syscall_num = __NR_recvmmsg,
	                                    });

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure()) {
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)MAX_RECV_BUF_SIZE);

	/* Parameter 2: fd (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (int64_t)server_fd);

	/* Parameter 3: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(3, (uint32_t)MAX_RECV_BUF_SIZE);

	/* Parameter 4: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(4, LONG_MESSAGE, DEFAULT_SNAPLEN);

	/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
	/* The server performs a 'recvmsg` so the server is the final destination of the packet
	 * while the client is the src. */
	evt_test->assert_tuple_inet_param(5,
	                                  PPM_AF_INET,
	                                  IPV4_CLIENT,
	                                  IPV4_SERVER,
	                                  IPV4_PORT_CLIENT_STRING,
	                                  IPV4_PORT_SERVER_STRING);

	/* Parameter 5: msg_control (type: PT_BYTEBUF) */
	evt_test->assert_empty_param(6);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(6);
}

TEST(SyscallExit, recvmmsgX_ipv6_udp_no_snaplen) {
	auto evt_test = get_syscall_event_test(__NR_recvmmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_fd, server_fd;
	evt_test->client_to_server_ipv6_udp(&client_fd,
	                                    &server_fd,
	                                    send_data{
	                                            .syscall_num = __NR_sendto,
	                                    },
	                                    recv_data{
	                                            .syscall_num = __NR_recvmmsg,
	                                    });

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure()) {
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)SHORT_MESSAGE_LEN);

	/* Parameter 2: fd (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (int64_t)server_fd);

	/* Parameter 3: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(3, (uint32_t)SHORT_MESSAGE_LEN);

	/* Parameter 4: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(4, SHORT_MESSAGE, SHORT_MESSAGE_LEN);

	/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
	/* The server performs a 'recvmmsg` so the server is the final destination of the packet
	 * while the client is the src. */
	evt_test->assert_tuple_inet6_param(5,
	                                   PPM_AF_INET6,
	                                   IPV6_CLIENT,
	                                   IPV6_SERVER,
	                                   IPV6_PORT_CLIENT_STRING,
	                                   IPV6_PORT_SERVER_STRING);

	/* Parameter 6: msg_control (type: PT_BYTEBUF) */
	evt_test->assert_empty_param(6);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(6);
}

TEST(SyscallExit, recvmmsgX_ipv6_udp_truncated) {
	auto evt_test = get_syscall_event_test(__NR_recvmmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_fd, server_fd;
	evt_test->client_to_server_ipv6_udp(&client_fd,
	                                    &server_fd,
	                                    send_data{
	                                            .syscall_num = __NR_sendto,
	                                            .greater_snaplen = true,
	                                    },
	                                    recv_data{
	                                            .syscall_num = __NR_recvmmsg,
	                                    });

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure()) {
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)MAX_RECV_BUF_SIZE);

	/* Parameter 2: fd (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (int64_t)server_fd);

	/* Parameter 3: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(3, (uint32_t)MAX_RECV_BUF_SIZE);

	/* Parameter 4: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(4, LONG_MESSAGE, DEFAULT_SNAPLEN);

	/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
	/* The server performs a 'recvmsg` so the server is the final destination of the packet
	 * while the client is the src. */
	evt_test->assert_tuple_inet6_param(5,
	                                   PPM_AF_INET6,
	                                   IPV6_CLIENT,
	                                   IPV6_SERVER,
	                                   IPV6_PORT_CLIENT_STRING,
	                                   IPV6_PORT_SERVER_STRING);

	/* Parameter 6: msg_control (type: PT_BYTEBUF) */
	evt_test->assert_empty_param(6);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(6);
}

TEST(SyscallExit, recvmmsgX_ipv4_tcp_connection_null_sockaddr) {
	auto evt_test = get_syscall_event_test(__NR_recvmmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_fd, server_fd;
	evt_test->client_to_server_ipv4_tcp(&client_fd,
	                                    &server_fd,
	                                    send_data{
	                                            .syscall_num = __NR_sendto,
	                                            .greater_snaplen = true,
	                                    },
	                                    recv_data{
	                                            .syscall_num = __NR_recvmmsg,
	                                            .null_sockaddr = true,
	                                    });

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure()) {
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)MAX_RECV_BUF_SIZE);

	/* Parameter 2: fd (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (int64_t)server_fd);

	/* Parameter 3: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(3, (uint32_t)MAX_RECV_BUF_SIZE);

	/* Parameter 3: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(4, LONG_MESSAGE, DEFAULT_SNAPLEN);

	if(evt_test->is_modern_bpf_engine()) {
		/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
		/* The server performs a 'recvmmsg` so the server is the final destination of the packet
		 * while the client is the src. */
		evt_test->assert_tuple_inet_param(5,
		                                  PPM_AF_INET,
		                                  IPV4_CLIENT,
		                                  IPV4_SERVER,
		                                  IPV4_PORT_CLIENT_STRING,
		                                  IPV4_PORT_SERVER_STRING);
	} else {
		evt_test->assert_empty_param(5);
		evt_test->assert_num_params_pushed(6);
		GTEST_SKIP() << "[RECVMSG_X]: we receive an empty tuple because the pointer to sockaddr is "
		                "NULL, but we should rely on kernel structs"
		             << std::endl;
	}

	/* Parameter 6: msg_control (type: PT_BYTEBUF) */
	evt_test->assert_empty_param(6);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(6);
}

TEST(SyscallExit, recvmmsgX_ipv4_udp_connection_null_sockaddr) {
	auto evt_test = get_syscall_event_test(__NR_recvmmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_fd, server_fd;
	evt_test->client_to_server_ipv4_udp(&client_fd,
	                                    &server_fd,
	                                    send_data{
	                                            .syscall_num = __NR_sendto,
	                                            .greater_snaplen = true,
	                                    },
	                                    recv_data{
	                                            .syscall_num = __NR_recvmmsg,
	                                            .null_sockaddr = true,
	                                    });

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure()) {
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)MAX_RECV_BUF_SIZE);

	/* Parameter 2: fd (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (int64_t)server_fd);

	/* Parameter 3: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(3, (uint32_t)MAX_RECV_BUF_SIZE);

	/* Parameter 3: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(4, LONG_MESSAGE, DEFAULT_SNAPLEN);

	if(evt_test->is_modern_bpf_engine()) {
		/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
		/* The server performs a 'recvmmsg` so the server is the final destination of the packet
		 * while the client is the src. */
		evt_test->assert_tuple_inet_param(5,
		                                  PPM_AF_INET,
		                                  IPV4_EMPTY,
		                                  IPV4_SERVER,
		                                  IPV4_PORT_EMPTY_STRING,
		                                  IPV4_PORT_SERVER_STRING);
	} else {
		evt_test->assert_empty_param(5);
		evt_test->assert_num_params_pushed(6);
		GTEST_SKIP() << "[RECVMSG_X]: we receive an empty tuple because the pointer to sockaddr is "
		                "NULL, but we should rely on kernel structs"
		             << std::endl;
	}

	/* Parameter 6: msg_control (type: PT_BYTEBUF) */
	evt_test->assert_empty_param(6);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(6);
}

TEST(SyscallExit, recvmmsgX_ipv4_tcp_connection_null_buffer) {
	auto evt_test = get_syscall_event_test(__NR_recvmmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_fd, server_fd;
	evt_test->client_to_server_ipv4_tcp(&client_fd,
	                                    &server_fd,
	                                    send_data{
	                                            .syscall_num = __NR_sendto,
	                                            .greater_snaplen = true,
	                                    },
	                                    recv_data{
	                                            .syscall_num = __NR_recvmmsg,
	                                            .null_receiver_buffer = true,
	                                    });

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure()) {
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)0);

	/* Parameter 2: fd (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (int64_t)server_fd);

	/* Parameter 3: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(3, (uint32_t)0);

	/* Parameter 3: data (type: PT_BYTEBUF) */
	evt_test->assert_empty_param(4);

	if(evt_test->is_modern_bpf_engine()) {
		/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
		/* The server performs a 'recvmmsg` so the server is the final destination of the packet
		 * while the client is the src. */
		evt_test->assert_tuple_inet_param(5,
		                                  PPM_AF_INET,
		                                  IPV4_CLIENT,
		                                  IPV4_SERVER,
		                                  IPV4_PORT_CLIENT_STRING,
		                                  IPV4_PORT_SERVER_STRING);
	} else {
		evt_test->assert_empty_param(5);
		evt_test->assert_num_params_pushed(6);
		GTEST_SKIP() << "[RECVMSG_X]: we receive an empty tuple because the pointer to sockaddr is "
		                "NULL, but we should rely on kernel structs"
		             << std::endl;
	}

	/* Parameter 6: msg_control (type: PT_BYTEBUF) */
	evt_test->assert_empty_param(6);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(6);
}

TEST(SyscallExit, recvmmsgX_ipv4_udp_connection_null_buffer) {
	auto evt_test = get_syscall_event_test(__NR_recvmmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_fd, server_fd;
	evt_test->client_to_server_ipv4_udp(&client_fd,
	                                    &server_fd,
	                                    send_data{
	                                            .syscall_num = __NR_sendto,
	                                            .greater_snaplen = true,
	                                    },
	                                    recv_data{
	                                            .syscall_num = __NR_recvmmsg,
	                                            .null_receiver_buffer = true,
	                                    });

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure()) {
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)0);

	/* Parameter 2: fd (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (int64_t)server_fd);

	/* Parameter 3: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(3, (uint32_t)0);

	/* Parameter 3: data (type: PT_BYTEBUF) */
	evt_test->assert_empty_param(4);

	/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
	/* The server performs a 'recvmmsg` so the server is the final destination of the packet
	 * while the client is the src. */
	evt_test->assert_tuple_inet_param(5,
	                                  PPM_AF_INET,
	                                  IPV4_CLIENT,
	                                  IPV4_SERVER,
	                                  IPV4_PORT_CLIENT_STRING,
	                                  IPV4_PORT_SERVER_STRING);

	/* Parameter 6: msg_control (type: PT_BYTEBUF) */
	evt_test->assert_empty_param(6);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(6);
}

TEST(SyscallExit, recvmmsgX_ipv4_tcp_multiple_messages) {
	auto evt_test = get_syscall_event_test(__NR_recvmmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_socket_fd = 0;
	int32_t server_socket_fd = 0;
	sockaddr_in client_addr = {};
	sockaddr_in server_addr = {};
	evt_test->connect_ipv4_client_to_server(&client_socket_fd,
	                                        &client_addr,
	                                        &server_socket_fd,
	                                        &server_addr);
	constexpr int vlen = 2;
	using recv_buffer = std::array<char, MAX_RECV_BUF_SIZE>;
	std::array<struct mmsghdr, vlen> mmsg = {};
	std::array<struct iovec, vlen> iov = {};
	std::array<recv_buffer, vlen> data = {};
	std::array<recv_buffer, vlen> names = {};

	for(int i = 0; i < vlen; i++) {
		auto &iov_item = iov.at(i);
		iov_item.iov_base = &data.at(i);
		iov_item.iov_len = 1;

		auto &m = mmsg.at(i);
		m.msg_len = 1;
		m.msg_hdr.msg_name = &names.at(i);
		m.msg_hdr.msg_namelen = MAX_RECV_BUF_SIZE;
		m.msg_hdr.msg_iov = &iov.at(i);
		m.msg_hdr.msg_iovlen = 1;
	}

	// send 2 messages
	int64_t sent_bytes = syscall(__NR_sendto,
	                             client_socket_fd,
	                             SHORT_MESSAGE,
	                             SHORT_MESSAGE_LEN,
	                             0,
	                             &server_addr,
	                             sizeof(server_addr));
	assert_syscall_state(SYSCALL_SUCCESS, "sendto (client)", sent_bytes, NOT_EQUAL, -1);

	sent_bytes = syscall(__NR_sendto,
	                     client_socket_fd,
	                     LONG_MESSAGE,
	                     LONG_MESSAGE_LEN,
	                     0,
	                     &server_addr,
	                     sizeof(server_addr));
	assert_syscall_state(SYSCALL_SUCCESS, "sendto (client)", sent_bytes, NOT_EQUAL, -1);

	int receive_socket_fd = syscall(__NR_accept4, server_socket_fd, NULL, NULL, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "accept4 (server)", receive_socket_fd, NOT_EQUAL, -1);
	int64_t received_messages =
	        syscall(__NR_recvmmsg, receive_socket_fd, mmsg.data(), vlen, 0, NULL);
	assert_syscall_state(SYSCALL_SUCCESS, "recvmmsg (server)", received_messages, EQUAL, vlen);

	/* Cleaning phase */
	syscall(__NR_shutdown, receive_socket_fd, 2);
	syscall(__NR_shutdown, server_socket_fd, 2);
	syscall(__NR_shutdown, client_socket_fd, 2);
	syscall(__NR_close, receive_socket_fd);
	syscall(__NR_close, server_socket_fd);
	syscall(__NR_close, client_socket_fd);

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	for(const auto &m : mmsg) {
		evt_test->assert_event_presence();

		if(HasFatalFailure()) {
			return;
		}

		evt_test->parse_event();

		evt_test->assert_header();

		/*=============================== ASSERT PARAMETERS  ===========================*/

		/* Parameter 1: res (type: PT_ERRNO) */
		evt_test->assert_numeric_param(1, (int64_t)m.msg_len);

		/* Parameter 2: fd (type: PT_FD) */
		evt_test->assert_numeric_param(2, (int64_t)receive_socket_fd);

		if(m.msg_len > DEFAULT_SNAPLEN) {
			/* Parameter 3: size (type: PT_UINT32) */
			evt_test->assert_numeric_param(3, (uint32_t)MAX_RECV_BUF_SIZE);

			/* Parameter 4: data (type: PT_BYTEBUF) */
			evt_test->assert_bytebuf_param(4, LONG_MESSAGE, DEFAULT_SNAPLEN);
		} else {
			/* Parameter 3: size (type: PT_UINT32) */
			evt_test->assert_numeric_param(3, (uint32_t)m.msg_len);

			/* Parameter 4: data (type: PT_BYTEBUF) */
			evt_test->assert_bytebuf_param(4, SHORT_MESSAGE, (uint32_t)m.msg_len);
		}

		/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
		if(evt_test->is_modern_bpf_engine()) {
			/* The server performs a 'recvmmsg` so the server is the final destination of the packet
			 * while the client is the src. */
			evt_test->assert_tuple_inet_param(5,
			                                  PPM_AF_INET,
			                                  IPV4_CLIENT,
			                                  IPV4_SERVER,
			                                  IPV4_PORT_CLIENT_STRING,
			                                  IPV4_PORT_SERVER_STRING);
		} else {
			/// TODO: If the socket is connected, the msg_name and msg_namelen members shall be
			/// ignored, but right now we use them to send data also in TCP connections so we need
			/// to change this behavior!
			evt_test->assert_empty_param(5);
			evt_test->assert_num_params_pushed(6);
		}

		/* Parameter 6: msg_control (type: PT_BYTEBUF) */
		evt_test->assert_empty_param(6);

		/*=============================== ASSERT PARAMETERS  ===========================*/

		evt_test->assert_num_params_pushed(6);
		/*=============================== ASSERT PARAMETERS  ===========================*/
	}
}

#endif

TEST(SyscallExit, recvmmsgX_fail) {
	auto evt_test = get_syscall_event_test(__NR_recvmmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t mock_fd = -1;
	struct mmsghdr *mmh = NULL;
	int flags = 0;
	assert_syscall_state(SYSCALL_FAILURE,
	                     "recvmmsg",
	                     syscall(__NR_recvmmsg, mock_fd, mmh, flags, NULL));
	int64_t errno_value = -errno;

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure()) {
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/* Parameter 2: fd (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)mock_fd);

	/* Parameter 3: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(3, (uint32_t)0);

	/* Parameter 4: data (type: PT_BYTEBUF) */
	evt_test->assert_empty_param(4);

	/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
	evt_test->assert_empty_param(5);

	/* Parameter 6: msg_control (type: PT_BYTEBUF) */
	evt_test->assert_empty_param(6);

	/*=============================== ASSERT PARAMETERS  ===========================*/
}

TEST(SyscallExit, recvmmsgX_ancillary_data) {
	auto evt_test = get_syscall_event_test(__NR_recvmmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_socket_fd = 0;
	int32_t server_socket_fd = 0;
	struct sockaddr_un client_addr = {};
	struct sockaddr_un server_addr = {};
	evt_test->connect_unix_tcp_client_to_server(&client_socket_fd,
	                                            &client_addr,
	                                            &server_socket_fd,
	                                            &server_addr);

	int64_t received_bytes, sent_bytes, msg_controllen;
	struct cmsghdr *cmsg;
	char cmsg_buf[CMSG_SPACE(sizeof(int))];

	struct iovec iov = {};
	iov.iov_base = (void *)LONG_MESSAGE;
	iov.iov_len = LONG_MESSAGE_LEN;

	/* We don't want to get any info about the connected socket so `addr` and `addrlen` are NULL. */
	int connected_socket_fd = syscall(__NR_accept4, server_socket_fd, NULL, NULL, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "accept (server)", connected_socket_fd, NOT_EQUAL, -1);

	/* Now we can fork. We still maintain the connected_socket_fd in both parent and child processes
	 */
	pid_t pid = fork();
	if(pid) {
		/* Create a socket. It is used to pass it to the child process, just for test purposes */
		int sock = socket(AF_UNIX, SOCK_STREAM, 0);
		msghdr msg = {};
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = cmsg_buf;
		msg.msg_controllen = sizeof(cmsg_buf);
		msg_controllen = msg.msg_controllen;

		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(sock));

		memcpy(CMSG_DATA(cmsg), &sock, sizeof(sock));

		sent_bytes = syscall(__NR_sendmsg, client_socket_fd, &msg, 0);
		assert_syscall_state(SYSCALL_SUCCESS, "sendmsg (client)", sent_bytes, NOT_EQUAL, -1);
		;

		int wstatus;
		waitpid(pid, &wstatus, 0);

		syscall(__NR_shutdown, sock);
		syscall(__NR_close, sock);
	} else {
		char buf[MAX_RECV_BUF_SIZE];
		iov = {};
		iov.iov_base = (void *)buf;
		iov.iov_len = sizeof(buf);

		struct mmsghdr mmh = {};
		mmh.msg_hdr.msg_iov = &iov;
		mmh.msg_hdr.msg_iovlen = 1;
		mmh.msg_hdr.msg_control = cmsg_buf;
		mmh.msg_hdr.msg_controllen = sizeof(cmsg_buf);

		uint32_t vlen = 1;
		int flags = 0;
		received_bytes = syscall(__NR_recvmmsg, connected_socket_fd, &mmh, vlen, flags, NULL);
		assert_syscall_state(SYSCALL_SUCCESS, "recvmmsg (server)", received_bytes, EQUAL, 1);
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

	if(HasFatalFailure()) {
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)MAX_RECV_BUF_SIZE);

	/* Parameter 2: fd (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)connected_socket_fd);

	/* Parameter 3: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(3, (uint32_t)MAX_RECV_BUF_SIZE);

	/* Parameter 4: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(4, LONG_MESSAGE, DEFAULT_SNAPLEN);

	/* Parameter 6: msg_control (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(6, (const char *)cmsg, msg_controllen);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(6);
}
#endif

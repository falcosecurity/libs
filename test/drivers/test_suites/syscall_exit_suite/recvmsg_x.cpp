#include "../../event_class/event_class.h"

#ifdef __NR_recvmsg

#if defined(__NR_accept4) && defined(__NR_connect) && defined(__NR_socket) &&         \
        defined(__NR_bind) && defined(__NR_listen) && defined(__NR_close) &&          \
        defined(__NR_setsockopt) && defined(__NR_shutdown) && defined(__NR_sendto) && \
        defined(__NR_sendmsg)

/*=============================== TCP ===========================*/

TEST(SyscallExit, recvmsgX_ipv4_tcp_message_shorter_than_snaplen) {
	auto evt_test = get_syscall_event_test(__NR_recvmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->client_to_server_ipv4_tcp(send_data{.syscall_num = __NR_sendto},
	                                    recv_data{.syscall_num = __NR_recvmsg});

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

	/* Parameter 2: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (uint32_t)SHORT_MESSAGE_LEN);

	/* Parameter 3: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(3, SHORT_MESSAGE, SHORT_MESSAGE_LEN);

	/* Parameter 4: tuple (type: PT_SOCKTUPLE) */
	if(evt_test->is_modern_bpf_engine()) {
		/* The server performs a 'recvmsg` so the server is the final destination of the packet
		 * while the client is the src. */
		evt_test->assert_tuple_inet_param(4,
		                                  PPM_AF_INET,
		                                  IPV4_CLIENT,
		                                  IPV4_SERVER,
		                                  IPV4_PORT_CLIENT_STRING,
		                                  IPV4_PORT_SERVER_STRING);
	} else {
		/// todo!: If the socket is connected, the msg_name and msg_namelen members shall be
		/// ignored, but right now we use them to send data also in TCP connections so we need to
		/// change this behavior!
		evt_test->assert_empty_param(4);
		evt_test->assert_num_params_pushed(5);
		GTEST_SKIP() << "[RECVMSG_X]: we receive an empty tuple but we have all the data in the "
		                "kernel to "
		                "obtain the correct tuple"
		             << std::endl;
	}

	/* Parameter 5: msg_control (type: PT_BYTEBUF) */
	evt_test->assert_empty_param(5);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

TEST(SyscallExit, recvmsgX_ipv4_tcp_message_longer_than_snaplen_truncated) {
	auto evt_test = get_syscall_event_test(__NR_recvmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->client_to_server_ipv4_tcp(
	        send_data{.syscall_num = __NR_sendto, .greater_snaplen = true},
	        recv_data{.syscall_num = __NR_recvmsg});

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

	/* Parameter 2: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (uint32_t)MAX_RECV_BUF_SIZE);

	/* Parameter 3: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(3, LONG_MESSAGE, DEFAULT_SNAPLEN);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

TEST(SyscallExit, recvmsgX_ipv4_tcp_message_longer_than_snaplen_not_truncated_fullcapture_port) {
	auto evt_test = get_syscall_event_test(__NR_recvmsg, EXIT_EVENT);

	evt_test->set_do_dynamic_snaplen(true);

	// Now the client port is in the range so we should see the full message not truncated by the
	// snaplen.
	evt_test->set_fullcapture_port_range(IPV4_PORT_CLIENT, IPV4_PORT_CLIENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->client_to_server_ipv4_tcp(
	        send_data{.syscall_num = __NR_sendto, .greater_snaplen = true},
	        recv_data{.syscall_num = __NR_recvmsg});

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->set_do_dynamic_snaplen(false);

	evt_test->assert_event_presence();

	/* we need to clean the values after we read our event because the kernel module
	 * flushes the ring buffers when we change this config.
	 */
	evt_test->set_fullcapture_port_range(0, 0);

	if(HasFatalFailure()) {
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)MAX_RECV_BUF_SIZE);

	/* Parameter 2: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (uint32_t)MAX_RECV_BUF_SIZE);

	/* Parameter 3: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(3, LONG_MESSAGE, MAX_RECV_BUF_SIZE);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

TEST(SyscallExit, recvmsgX_ipv6_tcp_message_not_truncated_fullcapture_port) {
	auto evt_test = get_syscall_event_test(__NR_recvmsg, EXIT_EVENT);

	evt_test->set_do_dynamic_snaplen(true);

	// Now the client port is in the range so we should see the full message not truncated by the
	// snaplen.
	evt_test->set_fullcapture_port_range(IPV6_PORT_CLIENT, IPV6_PORT_CLIENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->client_to_server_ipv6_tcp(
	        send_data{.syscall_num = __NR_sendto, .greater_snaplen = true},
	        recv_data{.syscall_num = __NR_recvmsg});

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->set_do_dynamic_snaplen(false);

	evt_test->assert_event_presence();

	/* we need to clean the values after we read our event because the kernel module
	 * flushes the ring buffers when we change this config.
	 */
	evt_test->set_fullcapture_port_range(0, 0);

	if(HasFatalFailure()) {
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)MAX_RECV_BUF_SIZE);

	/* Parameter 2: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (uint32_t)MAX_RECV_BUF_SIZE);

	/* Parameter 3: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(3, LONG_MESSAGE, MAX_RECV_BUF_SIZE);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

TEST(SyscallExit, recvmsgX_ipv4_tcp_NULL_sockaddr) {
	auto evt_test = get_syscall_event_test(__NR_recvmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->client_to_server_ipv4_tcp(
	        send_data{.syscall_num = __NR_sendto, .greater_snaplen = true},
	        recv_data{.syscall_num = __NR_recvmsg, .null_sockaddr = true});

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

	/* Parameter 2: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (uint32_t)MAX_RECV_BUF_SIZE);

	/* Parameter 3: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(3, LONG_MESSAGE, DEFAULT_SNAPLEN);

	if(evt_test->is_modern_bpf_engine()) {
		/* Parameter 4: tuple (type: PT_SOCKTUPLE) */
		evt_test->assert_tuple_inet_param(4,
		                                  PPM_AF_INET,
		                                  IPV4_CLIENT,
		                                  IPV4_SERVER,
		                                  IPV4_PORT_CLIENT_STRING,
		                                  IPV4_PORT_SERVER_STRING);
	} else {
		evt_test->assert_empty_param(4);
		GTEST_SKIP() << "[RECVMSG_X]: we rely on the addrlen provided by the kernel but this seems "
		                "to be always 0."
		             << "we should rely on kernel structs" << std::endl;
	}

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

// Even if the sockaddr is NULL we can retrieve the information from the kernel socket because we
// have a connection between client and server.
TEST(SyscallExit,
     recvmsgX_ipv4_tcp_message_longer_than_snaplen_not_truncated_fullcapture_port_NULL_sockaddr) {
	auto evt_test = get_syscall_event_test(__NR_recvmsg, EXIT_EVENT);

	evt_test->set_do_dynamic_snaplen(true);

	// Now the client port is in the range so we should see the full message not truncated by the
	// snaplen.
	evt_test->set_fullcapture_port_range(IPV4_PORT_CLIENT, IPV4_PORT_CLIENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->client_to_server_ipv4_tcp(
	        send_data{.syscall_num = __NR_sendto, .greater_snaplen = true},
	        recv_data{.syscall_num = __NR_recvmsg, .null_sockaddr = true});

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->set_do_dynamic_snaplen(false);

	evt_test->assert_event_presence();

	/* we need to clean the values after we read our event because the kernel module
	 * flushes the ring buffers when we change this config.
	 */
	evt_test->set_fullcapture_port_range(0, 0);

	if(HasFatalFailure()) {
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)MAX_RECV_BUF_SIZE);

	/* Parameter 2: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (uint32_t)MAX_RECV_BUF_SIZE);

	/* Parameter 3: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(3, LONG_MESSAGE, MAX_RECV_BUF_SIZE);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

TEST(SyscallExit, recvmsgX_ipv4_tcp_NULL_buffer) {
	auto evt_test = get_syscall_event_test(__NR_recvmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->client_to_server_ipv4_tcp(
	        send_data{.syscall_num = __NR_sendto, .greater_snaplen = true},
	        recv_data{.syscall_num = __NR_recvmsg, .null_receiver_buffer = true});

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

	/* Parameter 2: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (uint32_t)0);

	/* Parameter 3: data (type: PT_BYTEBUF) */
	evt_test->assert_empty_param(3);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

/*=============================== UDP ===========================*/

TEST(SyscallExit, recvmsgX_ipv4_udp_message_shorter_than_snaplen) {
	auto evt_test = get_syscall_event_test(__NR_recvmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->client_to_server_ipv4_udp(send_data{.syscall_num = __NR_sendto},
	                                    recv_data{.syscall_num = __NR_recvmsg});

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

	/* Parameter 2: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (uint32_t)SHORT_MESSAGE_LEN);

	/* Parameter 3: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(3, SHORT_MESSAGE, SHORT_MESSAGE_LEN);

	/* Parameter 4: tuple (type: PT_SOCKTUPLE) */
	evt_test->assert_tuple_inet_param(4,
	                                  PPM_AF_INET,
	                                  IPV4_CLIENT,
	                                  IPV4_SERVER,
	                                  IPV4_PORT_CLIENT_STRING,
	                                  IPV4_PORT_SERVER_STRING);

	/* Parameter 5: msg_control (type: PT_BYTEBUF) */
	evt_test->assert_empty_param(5);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

TEST(SyscallExit, recvmsgX_ipv4_udp_message_longer_than_snaplen_truncated) {
	auto evt_test = get_syscall_event_test(__NR_recvmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->client_to_server_ipv4_udp(
	        send_data{.syscall_num = __NR_sendto, .greater_snaplen = true},
	        recv_data{.syscall_num = __NR_recvmsg});

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

	/* Parameter 2: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (uint32_t)MAX_RECV_BUF_SIZE);

	/* Parameter 3: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(3, LONG_MESSAGE, DEFAULT_SNAPLEN);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

TEST(SyscallExit, recvmsgX_ipv4_udp_message_longer_than_snaplen_not_truncated_fullcapture_port) {
	auto evt_test = get_syscall_event_test(__NR_recvmsg, EXIT_EVENT);

	evt_test->set_do_dynamic_snaplen(true);

	// Now the client port is in the range so we should see the full message not truncated by the
	// snaplen.
	evt_test->set_fullcapture_port_range(IPV4_PORT_CLIENT, IPV4_PORT_CLIENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->client_to_server_ipv4_udp(
	        send_data{.syscall_num = __NR_sendto, .greater_snaplen = true},
	        recv_data{.syscall_num = __NR_recvmsg});

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->set_do_dynamic_snaplen(false);

	evt_test->assert_event_presence();

	evt_test->set_fullcapture_port_range(0, 0);

	if(HasFatalFailure()) {
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)MAX_RECV_BUF_SIZE);

	/* Parameter 2: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (uint32_t)MAX_RECV_BUF_SIZE);

	/* Parameter 3: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(3, LONG_MESSAGE, MAX_RECV_BUF_SIZE);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

TEST(SyscallExit, recvmsgX_ipv4_udp_NULL_sockaddr) {
	auto evt_test = get_syscall_event_test(__NR_recvmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->client_to_server_ipv4_udp(
	        send_data{.syscall_num = __NR_sendto, .greater_snaplen = true},
	        recv_data{.syscall_num = __NR_recvmsg, .null_sockaddr = true});

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

	/* Parameter 2: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (uint32_t)MAX_RECV_BUF_SIZE);

	/* Parameter 3: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(3, LONG_MESSAGE, DEFAULT_SNAPLEN);

	if(evt_test->is_modern_bpf_engine()) {
		/* Parameter 4: tuple (type: PT_SOCKTUPLE) */
		evt_test->assert_tuple_inet_param(4,
		                                  PPM_AF_INET,
		                                  IPV4_EMPTY,
		                                  IPV4_SERVER,
		                                  IPV4_PORT_EMPTY_STRING,
		                                  IPV4_PORT_SERVER_STRING);
	} else {
		evt_test->assert_empty_param(4);
		GTEST_SKIP() << "[RECVMSG_X]: we receive an empty tuple because the pointer to sockaddr is "
		                "NULL, but "
		                "we should rely on kernel structs"
		             << std::endl;
	}

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

// Even if the sockaddr is NULL we can retrieve the information from the kernel socket because we
// have a connection between client and server.
TEST(SyscallExit,
     recvmsgX_ipv4_udp_message_longer_than_snaplen_truncated_fullcapture_port_NULL_sockaddr) {
	auto evt_test = get_syscall_event_test(__NR_recvmsg, EXIT_EVENT);

	evt_test->set_do_dynamic_snaplen(true);

	// Now the client port is in the range so we should see the full message not truncated by the
	// snaplen.
	evt_test->set_fullcapture_port_range(IPV4_PORT_CLIENT, IPV4_PORT_CLIENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->client_to_server_ipv4_udp(
	        send_data{.syscall_num = __NR_sendto, .greater_snaplen = true},
	        recv_data{.syscall_num = __NR_recvmsg, .null_sockaddr = true});

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->set_do_dynamic_snaplen(false);

	evt_test->assert_event_presence();

	evt_test->set_fullcapture_port_range(0, 0);

	if(HasFatalFailure()) {
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)MAX_RECV_BUF_SIZE);

	/* Parameter 2: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (uint32_t)MAX_RECV_BUF_SIZE);

	/* Parameter 3: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(3, LONG_MESSAGE, DEFAULT_SNAPLEN);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

TEST(SyscallExit, recvmsgX_ipv4_udp_NULL_buffer) {
	auto evt_test = get_syscall_event_test(__NR_recvmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->client_to_server_ipv4_udp(
	        send_data{.syscall_num = __NR_sendto, .greater_snaplen = true},
	        recv_data{.syscall_num = __NR_recvmsg, .null_receiver_buffer = true});

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

	/* Parameter 2: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (uint32_t)0);

	/* Parameter 3: data (type: PT_BYTEBUF) */
	evt_test->assert_empty_param(3);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

// todo!: we could add a test in which we receive a message on 2 different iovec structs
#endif

TEST(SyscallExit, recvmsgX_fail) {
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

	if(HasFatalFailure()) {
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

TEST(SyscallExit, recvmsg_ancillary_data) {
	auto evt_test = get_syscall_event_test(__NR_recvmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_socket_fd = 0;
	int32_t server_socket_fd = 0;
	struct sockaddr_un client_addr = {};
	struct sockaddr_un server_addr = {};
	evt_test->connect_unix_client_to_server(&client_socket_fd,
	                                        &client_addr,
	                                        &server_socket_fd,
	                                        &server_addr);
	int64_t received_bytes, sent_bytes, msg_controllen;
	struct cmsghdr *cmsg;
	char cmsg_buf[CMSG_SPACE(sizeof(int))];
	struct iovec iov = {
	        .iov_base = (void *)LONG_MESSAGE,
	        .iov_len = LONG_MESSAGE_LEN,
	};

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
		char buf[LONG_MESSAGE_LEN];
		iov = {iov.iov_base = (void *)buf, iov.iov_len = sizeof(buf)};

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

	if(HasFatalFailure()) {
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)LONG_MESSAGE_LEN);

	/* Parameter 2: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (uint32_t)LONG_MESSAGE_LEN);

	/* Parameter 3: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(3, LONG_MESSAGE, DEFAULT_SNAPLEN);

	/* Parameter 5: msg_control (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(5, (const char *)cmsg, msg_controllen);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

#endif

#include "../../event_class/event_class.h"

#ifdef __NR_recvfrom

#if defined(__NR_accept4) && defined(__NR_connect) && defined(__NR_socket) && \
        defined(__NR_bind) && defined(__NR_listen) && defined(__NR_close) &&  \
        defined(__NR_setsockopt) && defined(__NR_shutdown) && defined(__NR_sendto)

/*=============================== TCP ===========================*/

TEST(SyscallExit, recvfromX_ipv4_tcp_message_not_truncated_by_snaplen) {
	auto evt_test = get_syscall_event_test(__NR_recvfrom, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->client_to_server_ipv4_tcp(send_data{.syscall_num = __NR_sendto},
	                                    recv_data{.syscall_num = __NR_recvfrom});

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

	/* Parameter 2: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(2, SHORT_MESSAGE, SHORT_MESSAGE_LEN);

	/* Parameter 3: tuple (type: PT_SOCKTUPLE) */
	/* The server performs a 'recvfrom` so the server is the final destination of the packet while
	 * the client is the src. */
	evt_test->assert_tuple_inet_param(3,
	                                  PPM_AF_INET,
	                                  IPV4_CLIENT,
	                                  IPV4_SERVER,
	                                  IPV4_PORT_CLIENT_STRING,
	                                  IPV4_PORT_SERVER_STRING);

	/* Parameter 5: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(5, MAX_RECV_BUF_SIZE);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

TEST(SyscallExit, recvfromX_ipv4_tcp_message_truncated_by_snaplen) {
	auto evt_test = get_syscall_event_test(__NR_recvfrom, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->client_to_server_ipv4_tcp(
	        send_data{.syscall_num = __NR_sendto, .greater_snaplen = true},
	        recv_data{.syscall_num = __NR_recvfrom});

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

	/* Parameter 2: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(2, LONG_MESSAGE, DEFAULT_SNAPLEN);

	/* Parameter 3: tuple (type: PT_SOCKTUPLE) */
	evt_test->assert_tuple_inet_param(3,
	                                  PPM_AF_INET,
	                                  IPV4_CLIENT,
	                                  IPV4_SERVER,
	                                  IPV4_PORT_CLIENT_STRING,
	                                  IPV4_PORT_SERVER_STRING);

	evt_test->assert_numeric_param(5, MAX_RECV_BUF_SIZE);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

TEST(SyscallExit, recvfromX_ipv4_tcp_message_not_truncated_fullcapture_port) {
	auto evt_test = get_syscall_event_test(__NR_recvfrom, EXIT_EVENT);

	evt_test->set_do_dynamic_snaplen(true);

	// Now the client port is in the range so we should see the full message not truncated by the
	// snaplen.
	evt_test->set_fullcapture_port_range(IPV4_PORT_CLIENT, IPV4_PORT_CLIENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->client_to_server_ipv4_tcp(
	        send_data{.syscall_num = __NR_sendto, .greater_snaplen = true},
	        recv_data{.syscall_num = __NR_recvfrom});

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

	/* Parameter 2: data (type: PT_BYTEBUF) */
	// Since the client port matches the fullcapture port range we should see the full message.
	evt_test->assert_bytebuf_param(2, LONG_MESSAGE, MAX_RECV_BUF_SIZE);

	/* Parameter 3: tuple (type: PT_SOCKTUPLE) */
	evt_test->assert_tuple_inet_param(3,
	                                  PPM_AF_INET,
	                                  IPV4_CLIENT,
	                                  IPV4_SERVER,
	                                  IPV4_PORT_CLIENT_STRING,
	                                  IPV4_PORT_SERVER_STRING);

	evt_test->assert_numeric_param(5, MAX_RECV_BUF_SIZE);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

TEST(SyscallExit, recvfromX_ipv4_tcp_message_not_truncated_DNS_snaplen) {
	auto evt_test = get_syscall_event_test(__NR_recvfrom, EXIT_EVENT);

	evt_test->set_do_dynamic_snaplen(true);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->client_to_server_ipv4_tcp(
	        send_data{.syscall_num = __NR_sendto, .greater_snaplen = true},
	        recv_data{.syscall_num = __NR_recvfrom},
	        IP_PORT_DNS,
	        IP_PORT_SERVER);

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->set_do_dynamic_snaplen(false);

	evt_test->assert_event_presence();

	if(HasFatalFailure()) {
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)MAX_RECV_BUF_SIZE);

	/* Parameter 2: data (type: PT_BYTEBUF) */
	// Since the client port matches the fullcapture port range we should see the full message.
	evt_test->assert_bytebuf_param(2, LONG_MESSAGE, MAX_RECV_BUF_SIZE);

	/* Parameter 3: tuple (type: PT_SOCKTUPLE) */
	evt_test->assert_tuple_inet_param(3,
	                                  PPM_AF_INET,
	                                  IPV4_CLIENT,
	                                  IPV4_SERVER,
	                                  IP_PORT_DNS_STRING,
	                                  IP_PORT_SERVER_STRING);

	evt_test->assert_numeric_param(5, MAX_RECV_BUF_SIZE);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

TEST(SyscallExit, recvfromX_ipv6_tcp_message_not_truncated_fullcapture_port) {
	auto evt_test = get_syscall_event_test(__NR_recvfrom, EXIT_EVENT);

	evt_test->set_do_dynamic_snaplen(true);

	// Now the client port is in the range so we should see the full message not truncated by the
	// snaplen.
	evt_test->set_fullcapture_port_range(IPV6_PORT_CLIENT, IPV6_PORT_CLIENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->client_to_server_ipv6_tcp(
	        send_data{.syscall_num = __NR_sendto, .greater_snaplen = true},
	        recv_data{.syscall_num = __NR_recvfrom});

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

	/* Parameter 2: data (type: PT_BYTEBUF) */
	// Since the client port matches the fullcapture port range we should see the full message.
	evt_test->assert_bytebuf_param(2, LONG_MESSAGE, MAX_RECV_BUF_SIZE);

	/* Parameter 3: tuple (type: PT_SOCKTUPLE) */
	evt_test->assert_tuple_inet6_param(3,
	                                   PPM_AF_INET6,
	                                   IPV6_CLIENT,
	                                   IPV6_SERVER,
	                                   IPV6_PORT_CLIENT_STRING,
	                                   IPV6_PORT_SERVER_STRING);

	evt_test->assert_numeric_param(5, MAX_RECV_BUF_SIZE);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

TEST(SyscallExit, recvfromX_ipv4_tcp_NULL_sockaddr) {
	auto evt_test = get_syscall_event_test(__NR_recvfrom, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->client_to_server_ipv4_tcp(
	        send_data{.syscall_num = __NR_sendto, .greater_snaplen = true},
	        recv_data{.syscall_num = __NR_recvfrom, .null_sockaddr = true});

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

	/* Parameter 2: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(2, LONG_MESSAGE, DEFAULT_SNAPLEN);

	/* Parameter 3: tuple (type: PT_SOCKTUPLE) */
	/* We have a connected socket so the kernel can retrieve the source address and port even if the
	 * userspace does not provide it.
	 */
	evt_test->assert_tuple_inet_param(3,
	                                  PPM_AF_INET,
	                                  IPV4_CLIENT,
	                                  IPV4_SERVER,
	                                  IPV4_PORT_CLIENT_STRING,
	                                  IPV4_PORT_SERVER_STRING);

	evt_test->assert_numeric_param(5, MAX_RECV_BUF_SIZE);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

// Even if the sockaddr is NULL we can retrieve the information from the kernel socket because we
// have a connection between client and server.
TEST(SyscallExit, recvfromX_ipv4_tcp_message_not_truncated_fullcapture_port_NULL_sockaddr) {
	auto evt_test = get_syscall_event_test(__NR_recvfrom, EXIT_EVENT);

	evt_test->set_do_dynamic_snaplen(true);

	// Now the client port is in the range so we should see the full message not truncated by the
	// snaplen.
	evt_test->set_fullcapture_port_range(IPV4_PORT_CLIENT, IPV4_PORT_CLIENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->client_to_server_ipv4_tcp(
	        send_data{.syscall_num = __NR_sendto, .greater_snaplen = true},
	        recv_data{.syscall_num = __NR_recvfrom, .null_sockaddr = true});

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

	/* Parameter 2: data (type: PT_BYTEBUF) */
	// Since the client port matches the fullcapture port range we should see the full message.
	evt_test->assert_bytebuf_param(2, LONG_MESSAGE, MAX_RECV_BUF_SIZE);

	/* Parameter 3: tuple (type: PT_SOCKTUPLE) */
	evt_test->assert_tuple_inet_param(3,
	                                  PPM_AF_INET,
	                                  IPV4_CLIENT,
	                                  IPV4_SERVER,
	                                  IPV4_PORT_CLIENT_STRING,
	                                  IPV4_PORT_SERVER_STRING);

	evt_test->assert_numeric_param(5, MAX_RECV_BUF_SIZE);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

TEST(SyscallExit, recvfromX_ipv4_tcp_NULL_buffer) {
	auto evt_test = get_syscall_event_test(__NR_recvfrom, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->client_to_server_ipv4_tcp(
	        send_data{.syscall_num = __NR_sendto, .greater_snaplen = true},
	        recv_data{.syscall_num = __NR_recvfrom, .null_receiver_buffer = true});

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
	// The return value is `0` since we received no bytes.
	evt_test->assert_numeric_param(1, (int64_t)0);

	/* Parameter 2: data (type: PT_BYTEBUF) */
	evt_test->assert_empty_param(2);

	/* Parameter 3: tuple (type: PT_SOCKTUPLE) */
	evt_test->assert_tuple_inet_param(3,
	                                  PPM_AF_INET,
	                                  IPV4_CLIENT,
	                                  IPV4_SERVER,
	                                  IPV4_PORT_CLIENT_STRING,
	                                  IPV4_PORT_SERVER_STRING);

	evt_test->assert_numeric_param(5, 0);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

/*=============================== UDP ===========================*/

TEST(SyscallExit, recvfromX_ipv4_udp_message_not_truncated_by_snaplen) {
	auto evt_test = get_syscall_event_test(__NR_recvfrom, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->client_to_server_ipv4_udp(send_data{.syscall_num = __NR_sendto},
	                                    recv_data{.syscall_num = __NR_recvfrom});

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

	/* Parameter 2: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(2, SHORT_MESSAGE, SHORT_MESSAGE_LEN);

	/* Parameter 3: tuple (type: PT_SOCKTUPLE) */
	evt_test->assert_tuple_inet_param(3,
	                                  PPM_AF_INET,
	                                  IPV4_CLIENT,
	                                  IPV4_SERVER,
	                                  IPV4_PORT_CLIENT_STRING,
	                                  IPV4_PORT_SERVER_STRING);

	evt_test->assert_numeric_param(5, MAX_RECV_BUF_SIZE);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

TEST(SyscallExit, recvfromX_ipv4_udp_message_truncated_by_snaplen) {
	auto evt_test = get_syscall_event_test(__NR_recvfrom, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->client_to_server_ipv4_udp(
	        send_data{.syscall_num = __NR_sendto, .greater_snaplen = true},
	        recv_data{.syscall_num = __NR_recvfrom});

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

	/* Parameter 2: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(2, LONG_MESSAGE, DEFAULT_SNAPLEN);

	/* Parameter 3: tuple (type: PT_SOCKTUPLE) */
	evt_test->assert_tuple_inet_param(3,
	                                  PPM_AF_INET,
	                                  IPV4_CLIENT,
	                                  IPV4_SERVER,
	                                  IPV4_PORT_CLIENT_STRING,
	                                  IPV4_PORT_SERVER_STRING);

	evt_test->assert_numeric_param(5, MAX_RECV_BUF_SIZE);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

TEST(SyscallExit, recvfromX_ipv4_udp_message_not_truncated_fullcapture_port) {
	auto evt_test = get_syscall_event_test(__NR_recvfrom, EXIT_EVENT);

	evt_test->set_do_dynamic_snaplen(true);

	// Now the client port is in the range so we should see the full message not truncated by the
	// snaplen.
	evt_test->set_fullcapture_port_range(IPV4_PORT_CLIENT, IPV4_PORT_CLIENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->client_to_server_ipv4_udp(
	        send_data{.syscall_num = __NR_sendto, .greater_snaplen = true},
	        recv_data{.syscall_num = __NR_recvfrom});

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

	/* Parameter 2: data (type: PT_BYTEBUF) */
	// Since the client port matches the fullcapture port range we should see the full message.
	evt_test->assert_bytebuf_param(2, LONG_MESSAGE, MAX_RECV_BUF_SIZE);

	/* Parameter 3: tuple (type: PT_SOCKTUPLE) */
	evt_test->assert_tuple_inet_param(3,
	                                  PPM_AF_INET,
	                                  IPV4_CLIENT,
	                                  IPV4_SERVER,
	                                  IPV4_PORT_CLIENT_STRING,
	                                  IPV4_PORT_SERVER_STRING);

	evt_test->assert_numeric_param(5, MAX_RECV_BUF_SIZE);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

TEST(SyscallExit, recvfromX_ipv4_udp_NULL_sockaddr) {
	auto evt_test = get_syscall_event_test(__NR_recvfrom, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->client_to_server_ipv4_udp(
	        send_data{.syscall_num = __NR_sendto, .greater_snaplen = true},
	        recv_data{.syscall_num = __NR_recvfrom, .null_sockaddr = true});

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

	/* Parameter 2: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(2, LONG_MESSAGE, DEFAULT_SNAPLEN);

	/* Parameter 3: tuple (type: PT_SOCKTUPLE) */
	/* If the `sockaddr` is `NULL` we cannot extract the sender ip and port.
	 * This is not a common case in real applications, it means we are ignoring the sender.
	 */
	evt_test->assert_tuple_inet_param(3,
	                                  PPM_AF_INET,
	                                  IPV4_EMPTY,
	                                  IPV4_SERVER,
	                                  IPV4_PORT_EMPTY_STRING,
	                                  IPV4_PORT_SERVER_STRING);

	evt_test->assert_numeric_param(5, MAX_RECV_BUF_SIZE);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

// If the `sockaddr` is `NULL` we cannot extract the sender ip and port. For this reason, the
// fullcapture port range logic won't work.
TEST(SyscallExit, recvfromX_ipv4_udp_message_truncated_fullcapture_port_NULL_sockaddr) {
	auto evt_test = get_syscall_event_test(__NR_recvfrom, EXIT_EVENT);

	evt_test->set_do_dynamic_snaplen(true);

	// Now the client port is in the range so we should see the full message not truncated by the
	// snaplen.
	evt_test->set_fullcapture_port_range(IPV4_PORT_CLIENT, IPV4_PORT_CLIENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->client_to_server_ipv4_udp(
	        send_data{.syscall_num = __NR_sendto, .greater_snaplen = true},
	        recv_data{.syscall_num = __NR_recvfrom, .null_sockaddr = true});

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

	/* Parameter 2: data (type: PT_BYTEBUF) */
	// Since the client port doesn't match the fullcapture port range we face a truncated message.
	evt_test->assert_bytebuf_param(2, LONG_MESSAGE, DEFAULT_SNAPLEN);

	/* Parameter 3: tuple (type: PT_SOCKTUPLE) */
	evt_test->assert_tuple_inet_param(3,
	                                  PPM_AF_INET,
	                                  IPV4_EMPTY,
	                                  IPV4_SERVER,
	                                  IPV4_PORT_EMPTY_STRING,
	                                  IPV4_PORT_SERVER_STRING);

	evt_test->assert_numeric_param(5, MAX_RECV_BUF_SIZE);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

TEST(SyscallExit, recvfromX_ipv4_udp_NULL_buffer) {
	auto evt_test = get_syscall_event_test(__NR_recvfrom, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->client_to_server_ipv4_udp(
	        send_data{.syscall_num = __NR_sendto, .greater_snaplen = true},
	        recv_data{.syscall_num = __NR_recvfrom, .null_receiver_buffer = true});

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
	// The return value is `0` since we received no bytes.
	evt_test->assert_numeric_param(1, (int64_t)0);

	/* Parameter 2: data (type: PT_BYTEBUF) */
	evt_test->assert_empty_param(2);

	/* Parameter 3: tuple (type: PT_SOCKTUPLE) */
	evt_test->assert_tuple_inet_param(3,
	                                  PPM_AF_INET,
	                                  IPV4_CLIENT,
	                                  IPV4_SERVER,
	                                  IPV4_PORT_CLIENT_STRING,
	                                  IPV4_PORT_SERVER_STRING);

	evt_test->assert_numeric_param(5, 0);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}
#endif

TEST(SyscallExit, recvfromX_fail) {
	auto evt_test = get_syscall_event_test(__NR_recvfrom, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t mock_fd = -1;
	char received_data[MAX_RECV_BUF_SIZE];
	socklen_t received_data_len = MAX_RECV_BUF_SIZE;
	uint32_t flags = 0;
	sockaddr* src_addr = NULL;
	socklen_t* addrlen = NULL;
	assert_syscall_state(SYSCALL_FAILURE,
	                     "recvfrom",
	                     syscall(__NR_recvfrom,
	                             mock_fd,
	                             received_data,
	                             received_data_len,
	                             flags,
	                             src_addr,
	                             addrlen));
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

	/* Parameter 2: data (type: PT_BYTEBUF) */
	evt_test->assert_empty_param(2);

	/* Parameter 3: tuple (type: PT_SOCKTUPLE) */
	evt_test->assert_empty_param(3);

	evt_test->assert_numeric_param(5, MAX_RECV_BUF_SIZE);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

#endif

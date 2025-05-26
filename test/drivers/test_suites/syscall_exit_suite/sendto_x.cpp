#include "../../event_class/event_class.h"

#ifdef __NR_sendto

#if defined(__NR_connect) && defined(__NR_socket) && defined(__NR_bind) && defined(__NR_listen) && \
        defined(__NR_close) && defined(__NR_setsockopt) && defined(__NR_shutdown)

/*=============================== TCP ===========================*/

TEST(SyscallExit, sendtoX_ipv4_tcp_message_not_truncated_by_snaplen) {
	auto evt_test = get_syscall_event_test(__NR_sendto, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_fd, server_fd;
	evt_test->client_to_server_ipv4_tcp(&client_fd,
	                                    &server_fd,
	                                    send_data{.syscall_num = __NR_sendto});

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

	/* Parameter 3: fd (type: PT_FD) */
	evt_test->assert_numeric_param(3, (int64_t)client_fd);

	/* Parameter 4: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(4, (uint32_t)SHORT_MESSAGE_LEN);

	/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
	evt_test->assert_tuple_inet_param(5,
	                                  PPM_AF_INET,
	                                  IPV4_CLIENT,
	                                  IPV4_SERVER,
	                                  IPV4_PORT_CLIENT_STRING,
	                                  IPV4_PORT_SERVER_STRING);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

TEST(SyscallExit, sendtoX_ipv4_tcp_message_truncated_by_snaplen) {
	auto evt_test = get_syscall_event_test(__NR_sendto, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_fd, server_fd;
	evt_test->client_to_server_ipv4_tcp(
	        &client_fd,
	        &server_fd,
	        send_data{.syscall_num = __NR_sendto, .greater_snaplen = true});

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
	evt_test->assert_numeric_param(1, (int64_t)LONG_MESSAGE_LEN);

	/* Parameter 2: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(2, LONG_MESSAGE, DEFAULT_SNAPLEN);

	/* Parameter 3: fd (type: PT_FD) */
	evt_test->assert_numeric_param(3, (int64_t)client_fd);

	/* Parameter 4: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(4, (uint32_t)LONG_MESSAGE_LEN);

	/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
	evt_test->assert_tuple_inet_param(5,
	                                  PPM_AF_INET,
	                                  IPV4_CLIENT,
	                                  IPV4_SERVER,
	                                  IPV4_PORT_CLIENT_STRING,
	                                  IPV4_PORT_SERVER_STRING);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

TEST(SyscallExit, sendtoX_ipv4_tcp_message_not_truncated_fullcapture_port) {
	auto evt_test = get_syscall_event_test(__NR_sendto, EXIT_EVENT);

	evt_test->set_do_dynamic_snaplen(true);

	// In sendto the missing one is the server port because it is the destination port.
	evt_test->set_fullcapture_port_range(IPV4_PORT_SERVER, IPV4_PORT_SERVER);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_fd, server_fd;
	evt_test->client_to_server_ipv4_tcp(
	        &client_fd,
	        &server_fd,
	        send_data{.syscall_num = __NR_sendto, .greater_snaplen = true});

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
	evt_test->assert_numeric_param(1, (int64_t)LONG_MESSAGE_LEN);

	/* Parameter 2: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(2, LONG_MESSAGE, LONG_MESSAGE_LEN);

	/* Parameter 3: fd (type: PT_FD) */
	evt_test->assert_numeric_param(3, (int64_t)client_fd);

	/* Parameter 4: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(4, (uint32_t)LONG_MESSAGE_LEN);

	/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
	evt_test->assert_tuple_inet_param(5,
	                                  PPM_AF_INET,
	                                  IPV4_CLIENT,
	                                  IPV4_SERVER,
	                                  IPV4_PORT_CLIENT_STRING,
	                                  IPV4_PORT_SERVER_STRING);
	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

TEST(SyscallExit, sendtoX_ipv4_tcp_message_not_truncated_DNS_snaplen) {
	auto evt_test = get_syscall_event_test(__NR_sendto, EXIT_EVENT);

	evt_test->set_do_dynamic_snaplen(true);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	// The remote port is the DNS one so the snaplen should be increased.
	int32_t client_fd, server_fd;
	evt_test->client_to_server_ipv4_tcp(
	        &client_fd,
	        &server_fd,
	        send_data{.syscall_num = __NR_sendto, .greater_snaplen = true},
	        recv_data{.syscall_num = 0, .skip_recv_phase = true},
	        IP_PORT_CLIENT,
	        IP_PORT_DNS);

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
	evt_test->assert_numeric_param(1, (int64_t)LONG_MESSAGE_LEN);

	/* Parameter 2: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(2, LONG_MESSAGE, LONG_MESSAGE_LEN);

	/* Parameter 3: fd (type: PT_FD) */
	evt_test->assert_numeric_param(3, (int64_t)client_fd);

	/* Parameter 4: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(4, (uint32_t)LONG_MESSAGE_LEN);

	/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
	evt_test->assert_tuple_inet_param(5,
	                                  PPM_AF_INET,
	                                  IPV4_CLIENT,
	                                  IPV4_SERVER,
	                                  IPV4_PORT_CLIENT_STRING,
	                                  std::to_string(PPM_PORT_DNS).c_str());

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

TEST(SyscallExit, sendtoX_ipv6_tcp_message_not_truncated_fullcapture_port) {
	auto evt_test = get_syscall_event_test(__NR_sendto, EXIT_EVENT);

	evt_test->set_do_dynamic_snaplen(true);

	// In sendto the missing one is the server port because it is the destination port.
	evt_test->set_fullcapture_port_range(IPV6_PORT_SERVER, IPV6_PORT_SERVER);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_fd, server_fd;
	evt_test->client_to_server_ipv4_tcp(
	        &client_fd,
	        &server_fd,
	        send_data{.syscall_num = __NR_sendto, .greater_snaplen = true});

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
	evt_test->assert_numeric_param(1, (int64_t)LONG_MESSAGE_LEN);

	/* Parameter 2: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(2, LONG_MESSAGE, LONG_MESSAGE_LEN);

	/* Parameter 3: fd (type: PT_FD) */
	evt_test->assert_numeric_param(3, (int64_t)client_fd);

	/* Parameter 4: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(4, (uint32_t)LONG_MESSAGE_LEN);

	/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
	evt_test->assert_tuple_inet_param(5,
	                                  PPM_AF_INET,
	                                  IPV4_CLIENT,
	                                  IPV4_SERVER,
	                                  IPV4_PORT_CLIENT_STRING,
	                                  IPV4_PORT_SERVER_STRING);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

TEST(SyscallExit, sendtoX_ipv4_tcp_message_not_truncated_fullcapture_port_NULL_sockaddr) {
	auto evt_test = get_syscall_event_test(__NR_sendto, EXIT_EVENT);

	evt_test->set_do_dynamic_snaplen(true);

	evt_test->set_fullcapture_port_range(IPV4_PORT_SERVER, IPV4_PORT_SERVER);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_fd, server_fd;
	evt_test->client_to_server_ipv4_tcp(
	        &client_fd,
	        &server_fd,
	        send_data{.syscall_num = __NR_sendto, .greater_snaplen = true, .null_sockaddr = true});

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
	evt_test->assert_numeric_param(1, (int64_t)LONG_MESSAGE_LEN);

	/* Parameter 2: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(2, LONG_MESSAGE, LONG_MESSAGE_LEN);

	/* Parameter 3: fd (type: PT_FD) */
	evt_test->assert_numeric_param(3, (int64_t)client_fd);

	/* Parameter 4: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(4, (uint32_t)LONG_MESSAGE_LEN);

	/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
	evt_test->assert_tuple_inet_param(5,
	                                  PPM_AF_INET,
	                                  IPV4_CLIENT,
	                                  IPV4_SERVER,
	                                  IPV4_PORT_CLIENT_STRING,
	                                  IPV4_PORT_SERVER_STRING);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

/*=============================== UDP ===========================*/

TEST(SyscallExit, sendtoX_ipv4_udp_message_not_truncated_by_snaplen) {
	auto evt_test = get_syscall_event_test(__NR_sendto, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_fd, server_fd;
	evt_test->client_to_server_ipv4_udp(&client_fd,
	                                    &server_fd,
	                                    send_data{.syscall_num = __NR_sendto});

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

	/* Parameter 3: fd (type: PT_FD) */
	evt_test->assert_numeric_param(3, (int64_t)client_fd);

	/* Parameter 4: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(4, (uint32_t)SHORT_MESSAGE_LEN);

	/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
	evt_test->assert_tuple_inet_param(5,
	                                  PPM_AF_INET,
	                                  IPV4_CLIENT,
	                                  IPV4_SERVER,
	                                  IPV4_PORT_CLIENT_STRING,
	                                  IPV4_PORT_SERVER_STRING);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

TEST(SyscallExit, sendtoX_ipv4_udp_message_truncated_by_snaplen) {
	auto evt_test = get_syscall_event_test(__NR_sendto, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_fd, server_fd;
	evt_test->client_to_server_ipv4_udp(
	        &client_fd,
	        &server_fd,
	        send_data{.syscall_num = __NR_sendto, .greater_snaplen = true});

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
	evt_test->assert_numeric_param(1, (int64_t)LONG_MESSAGE_LEN);

	/* Parameter 2: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(2, LONG_MESSAGE, DEFAULT_SNAPLEN);

	/* Parameter 3: fd (type: PT_FD) */
	evt_test->assert_numeric_param(3, (int64_t)client_fd);

	/* Parameter 4: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(4, (uint32_t)LONG_MESSAGE_LEN);

	/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
	evt_test->assert_tuple_inet_param(5,
	                                  PPM_AF_INET,
	                                  IPV4_CLIENT,
	                                  IPV4_SERVER,
	                                  IPV4_PORT_CLIENT_STRING,
	                                  IPV4_PORT_SERVER_STRING);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

TEST(SyscallExit, sendtoX_ipv4_udp_message_not_truncated_fullcapture_port) {
	auto evt_test = get_syscall_event_test(__NR_sendto, EXIT_EVENT);

	evt_test->set_do_dynamic_snaplen(true);

	evt_test->set_fullcapture_port_range(IPV4_PORT_SERVER, IPV4_PORT_SERVER);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_fd, server_fd;
	evt_test->client_to_server_ipv4_udp(
	        &client_fd,
	        &server_fd,
	        send_data{.syscall_num = __NR_sendto, .greater_snaplen = true});

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
	evt_test->assert_numeric_param(1, (int64_t)LONG_MESSAGE_LEN);

	/* Parameter 2: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(2, LONG_MESSAGE, LONG_MESSAGE_LEN);

	/* Parameter 3: fd (type: PT_FD) */
	evt_test->assert_numeric_param(3, (int64_t)client_fd);

	/* Parameter 4: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(4, (uint32_t)LONG_MESSAGE_LEN);

	/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
	evt_test->assert_tuple_inet_param(5,
	                                  PPM_AF_INET,
	                                  IPV4_CLIENT,
	                                  IPV4_SERVER,
	                                  IPV4_PORT_CLIENT_STRING,
	                                  IPV4_PORT_SERVER_STRING);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

// We cannot call a sendto without a destination address in UDP. Errno: 89 err_message: Destination
// address required. TEST(SyscallExit,
// sendtoX_ipv4_udp_message_not_truncated_fullcapture_port_NULL_sockaddr)
#endif

TEST(SyscallExit, sendtoX_fail) {
	auto evt_test = get_syscall_event_test(__NR_sendto, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t mock_fd = -1;
	char sent_data[DEFAULT_SNAPLEN / 2] = "some-data";
	size_t len = DEFAULT_SNAPLEN / 2;
	uint32_t sendto_flags = 0;
	struct sockaddr* dest_addr = NULL;
	socklen_t addrlen = 0;

	assert_syscall_state(
	        SYSCALL_FAILURE,
	        "sendto",
	        syscall(__NR_sendto, mock_fd, sent_data, len, sendto_flags, dest_addr, addrlen));
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
	evt_test->assert_bytebuf_param(2, sent_data, DEFAULT_SNAPLEN / 2);

	/* Parameter 3: fd (type: PT_FD) */
	evt_test->assert_numeric_param(3, (int64_t)mock_fd);

	/* Parameter 4: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(4, (uint32_t)len);

	/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
	evt_test->assert_empty_param(5);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

TEST(SyscallExit, sendtoX_empty) {
	auto evt_test = get_syscall_event_test(__NR_sendto, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t mock_fd = -1;
	char* sent_data = NULL;
	size_t len = 0;
	uint32_t sendto_flags = 0;
	struct sockaddr* dest_addr = NULL;
	socklen_t addrlen = 0;

	assert_syscall_state(
	        SYSCALL_FAILURE,
	        "sendto",
	        syscall(__NR_sendto, mock_fd, sent_data, len, sendto_flags, dest_addr, addrlen));
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

	/* Parameter 3: fd (type: PT_FD) */
	evt_test->assert_numeric_param(3, (int64_t)mock_fd);

	/* Parameter 4: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(4, (uint32_t)len);

	/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
	evt_test->assert_empty_param(5);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

#endif /* __NR_sendmsg */

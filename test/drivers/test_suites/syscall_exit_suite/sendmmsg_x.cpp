#include "../../event_class/event_class.h"

#ifdef __NR_sendmmsg

#if defined(__NR_connect) && defined(__NR_socket) && defined(__NR_bind) && defined(__NR_listen) && \
        defined(__NR_close) && defined(__NR_setsockopt) && defined(__NR_shutdown)

TEST(SyscallExit, sendmmsgX_ipv4_tcp_message_no_snaplen) {
	auto evt_test = get_syscall_event_test(__NR_sendmmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_fd, server_fd;
	evt_test->client_to_server_ipv4_tcp(&client_fd,
	                                    &server_fd,
	                                    send_data{.syscall_num = __NR_sendmmsg});

	/*=============================== TRIGGER SYSCALL  ===========================*/

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
	evt_test->assert_numeric_param(2, (int64_t)client_fd);

	/* Parameter 3: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(3, (uint32_t)SHORT_MESSAGE_LEN);

	/* Parameter 4: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(4, SHORT_MESSAGE, SHORT_MESSAGE_LEN);

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

TEST(SyscallExit, sendmmsgX_ipv4_tcp_truncated) {
	auto evt_test = get_syscall_event_test(__NR_sendmmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_fd, server_fd;
	evt_test->client_to_server_ipv4_tcp(&client_fd,
	                                    &server_fd,
	                                    send_data{
	                                            .syscall_num = __NR_sendmmsg,
	                                            .greater_snaplen = true,
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
	evt_test->assert_numeric_param(1, (int64_t)LONG_MESSAGE_LEN);

	/* Parameter 2: fd (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (int64_t)client_fd);

	/* Parameter 3: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(3, (uint32_t)LONG_MESSAGE_LEN);

	/* Parameter 4: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(4, LONG_MESSAGE, DEFAULT_SNAPLEN);

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

TEST(SyscallExit, sendmmsgX_ipv6_tcp_message_no_snaplen) {
	auto evt_test = get_syscall_event_test(__NR_sendmmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_fd, server_fd;
	evt_test->client_to_server_ipv6_tcp(&client_fd,
	                                    &server_fd,
	                                    send_data{.syscall_num = __NR_sendmmsg});

	/*=============================== TRIGGER SYSCALL  ===========================*/

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
	evt_test->assert_numeric_param(2, (int64_t)client_fd);

	/* Parameter 3: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(3, (uint32_t)SHORT_MESSAGE_LEN);

	/* Parameter 4: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(4, SHORT_MESSAGE, SHORT_MESSAGE_LEN);

	/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
	evt_test->assert_tuple_inet6_param(5,
	                                   PPM_AF_INET6,
	                                   IPV6_CLIENT,
	                                   IPV6_SERVER,
	                                   IPV6_PORT_CLIENT_STRING,
	                                   IPV6_PORT_SERVER_STRING);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

TEST(SyscallExit, sendmmsgX_ipv6_tcp_truncated) {
	auto evt_test = get_syscall_event_test(__NR_sendmmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_fd, server_fd;
	evt_test->client_to_server_ipv6_tcp(&client_fd,
	                                    &server_fd,
	                                    send_data{
	                                            .syscall_num = __NR_sendmmsg,
	                                            .greater_snaplen = true,
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
	evt_test->assert_numeric_param(1, (int64_t)LONG_MESSAGE_LEN);

	/* Parameter 2: fd (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (int64_t)client_fd);

	/* Parameter 3: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(3, (uint32_t)LONG_MESSAGE_LEN);

	/* Parameter 4: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(4, LONG_MESSAGE, DEFAULT_SNAPLEN);

	/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
	evt_test->assert_tuple_inet6_param(5,
	                                   PPM_AF_INET6,
	                                   IPV6_CLIENT,
	                                   IPV6_SERVER,
	                                   IPV6_PORT_CLIENT_STRING,
	                                   IPV6_PORT_SERVER_STRING);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

TEST(SyscallExit, sendmmsgX_ipv4_udp_message_no_snaplen) {
	auto evt_test = get_syscall_event_test(__NR_sendmmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_fd, server_fd;
	evt_test->client_to_server_ipv4_udp(&client_fd,
	                                    &server_fd,
	                                    send_data{.syscall_num = __NR_sendmmsg});

	/*=============================== TRIGGER SYSCALL  ===========================*/

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
	evt_test->assert_numeric_param(2, (int64_t)client_fd);

	/* Parameter 3: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(3, (uint32_t)SHORT_MESSAGE_LEN);

	/* Parameter 4: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(4, SHORT_MESSAGE, SHORT_MESSAGE_LEN);

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

TEST(SyscallExit, sendmmsgX_ipv4_udp_truncated) {
	auto evt_test = get_syscall_event_test(__NR_sendmmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_fd, server_fd;
	evt_test->client_to_server_ipv4_udp(&client_fd,
	                                    &server_fd,
	                                    send_data{
	                                            .syscall_num = __NR_sendmmsg,
	                                            .greater_snaplen = true,
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
	evt_test->assert_numeric_param(1, (int64_t)LONG_MESSAGE_LEN);

	/* Parameter 2: fd (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (int64_t)client_fd);

	/* Parameter 3: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(3, (uint32_t)LONG_MESSAGE_LEN);

	/* Parameter 4: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(4, LONG_MESSAGE, DEFAULT_SNAPLEN);

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

TEST(SyscallExit, sendmmsgX_ipv6_udp_message_no_snaplen) {
	auto evt_test = get_syscall_event_test(__NR_sendmmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_fd, server_fd;
	evt_test->client_to_server_ipv6_udp(&client_fd,
	                                    &server_fd,
	                                    send_data{.syscall_num = __NR_sendmmsg});

	/*=============================== TRIGGER SYSCALL  ===========================*/

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
	evt_test->assert_numeric_param(2, (int64_t)client_fd);

	/* Parameter 3: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(3, (uint32_t)SHORT_MESSAGE_LEN);

	/* Parameter 4: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(4, SHORT_MESSAGE, SHORT_MESSAGE_LEN);

	/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
	evt_test->assert_tuple_inet6_param(5,
	                                   PPM_AF_INET6,
	                                   IPV6_CLIENT,
	                                   IPV6_SERVER,
	                                   IPV6_PORT_CLIENT_STRING,
	                                   IPV6_PORT_SERVER_STRING);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

TEST(SyscallExit, sendmmsgX_ipv6_udp_truncated) {
	auto evt_test = get_syscall_event_test(__NR_sendmmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_fd, server_fd;
	evt_test->client_to_server_ipv6_udp(&client_fd,
	                                    &server_fd,
	                                    send_data{
	                                            .syscall_num = __NR_sendmmsg,
	                                            .greater_snaplen = true,
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
	evt_test->assert_numeric_param(1, (int64_t)LONG_MESSAGE_LEN);

	/* Parameter 2: fd (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (int64_t)client_fd);

	/* Parameter 3: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(3, (uint32_t)LONG_MESSAGE_LEN);

	/* Parameter 4: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(4, LONG_MESSAGE, DEFAULT_SNAPLEN);

	/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
	evt_test->assert_tuple_inet6_param(5,
	                                   PPM_AF_INET6,
	                                   IPV6_CLIENT,
	                                   IPV6_SERVER,
	                                   IPV6_PORT_CLIENT_STRING,
	                                   IPV6_PORT_SERVER_STRING);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

#endif

TEST(SyscallExit, sendmmsgX_fail) {
	auto evt_test = get_syscall_event_test(__NR_sendmmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t mock_fd = -1;
	struct iovec iov = {};

	static char sent_data_1[DEFAULT_SNAPLEN / 2] = "some-data";
	iov.iov_base = sent_data_1;
	iov.iov_len = sizeof(sent_data_1);

	struct mmsghdr msg = {};
	msg.msg_hdr.msg_iov = &iov;
	msg.msg_hdr.msg_iovlen = 1;

	uint32_t vlen = 1;
	int flags = 0;
	assert_syscall_state(SYSCALL_FAILURE,
	                     "sendmmsg",
	                     syscall(__NR_sendmmsg, mock_fd, &msg, vlen, flags));
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

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

TEST(SyscallExit, sendmmsgX_null_iovec) {
	auto evt_test = get_syscall_event_test(__NR_sendmmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t mock_fd = -1;

	struct mmsghdr msg = {};
	msg.msg_hdr.msg_iov = NULL;
	/* here we pass a wrong `iovlen` to check the behavior */
	msg.msg_hdr.msg_iovlen = 3;

	uint32_t vlen = 1;
	int flags = 0;
	assert_syscall_state(SYSCALL_FAILURE,
	                     "sendmmsg",
	                     syscall(__NR_sendmmsg, mock_fd, &msg, vlen, flags));
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

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

TEST(SyscallExit, sendmmsgX_null_mmsghdr) {
	auto evt_test = get_syscall_event_test(__NR_sendmmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t mock_fd = -1;

	uint32_t vlen = 1;
	int flags = 0;
	assert_syscall_state(SYSCALL_FAILURE,
	                     "sendmmsg",
	                     syscall(__NR_sendmmsg, mock_fd, NULL, vlen, flags));
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

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

TEST(SyscallExit, sendmmsg_multiple_messages_ipv4) {
	auto evt_test = get_syscall_event_test(__NR_sendmmsg, EXIT_EVENT);

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

	std::array<struct iovec, 2> iov = {};
	iov[0].iov_base = (void*)SHORT_MESSAGE;
	iov[0].iov_len = SHORT_MESSAGE_LEN;
	iov[1].iov_base = (void*)LONG_MESSAGE;
	iov[1].iov_len = LONG_MESSAGE_LEN;

	std::array<struct mmsghdr, 2> msgs = {};
	for(auto& m : msgs) {
		m.msg_hdr.msg_name = (sockaddr*)&server_addr;
		m.msg_hdr.msg_namelen = sizeof(server_addr);
	}
	msgs[0].msg_hdr.msg_iov = &iov.at(0);
	msgs[0].msg_hdr.msg_iovlen = 1;
	msgs[1].msg_hdr.msg_iov = &iov.at(1);
	msgs[1].msg_hdr.msg_iovlen = 1;

	uint32_t vlen = msgs.size();
	int flags = 0;
	assert_syscall_state(SYSCALL_SUCCESS,
	                     "sendmmsg (client)",
	                     syscall(__NR_sendmmsg, client_socket_fd, msgs.data(), vlen, flags),
	                     EQUAL,
	                     vlen);

	/* Cleaning phase */
	syscall(__NR_shutdown, server_socket_fd, 2);
	syscall(__NR_shutdown, client_socket_fd, 2);
	syscall(__NR_close, server_socket_fd);
	syscall(__NR_close, client_socket_fd);

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->disable_capture();

	for(const auto& m : msgs) {
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
		evt_test->assert_numeric_param(2, (int64_t)client_socket_fd);

		if(m.msg_len > DEFAULT_SNAPLEN) {
			/* Parameter 3: size (type: PT_UINT32) */
			evt_test->assert_numeric_param(3, LONG_MESSAGE_LEN);

			/* Parameter 4: data (type: PT_BYTEBUF) */
			evt_test->assert_bytebuf_param(4, LONG_MESSAGE, DEFAULT_SNAPLEN);
		} else {
			/* Parameter 3: size (type: PT_UINT32) */
			evt_test->assert_numeric_param(3, (uint32_t)m.msg_len);

			/* Parameter 4: data (type: PT_BYTEBUF) */
			evt_test->assert_bytebuf_param(4, SHORT_MESSAGE, (int32_t)m.msg_len);
		}

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
}

TEST(SyscallExit, sendmmsg_multiple_messages_ipv6) {
	auto evt_test = get_syscall_event_test(__NR_sendmmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_socket_fd = 0;
	int32_t server_socket_fd = 0;
	sockaddr_in6 client_addr = {};
	sockaddr_in6 server_addr = {};
	evt_test->connect_ipv6_client_to_server(&client_socket_fd,
	                                        &client_addr,
	                                        &server_socket_fd,
	                                        &server_addr);

	std::array<struct iovec, 2> iov = {};
	iov[0].iov_base = (void*)SHORT_MESSAGE;
	iov[0].iov_len = SHORT_MESSAGE_LEN;
	iov[1].iov_base = (void*)LONG_MESSAGE;
	iov[1].iov_len = LONG_MESSAGE_LEN;

	std::array<struct mmsghdr, 2> msgs = {};
	for(auto& m : msgs) {
		m.msg_hdr.msg_name = (sockaddr*)&server_addr;
		m.msg_hdr.msg_namelen = sizeof(server_addr);
	}
	msgs[0].msg_hdr.msg_iov = &iov.at(0);
	msgs[0].msg_hdr.msg_iovlen = 1;
	msgs[1].msg_hdr.msg_iov = &iov.at(1);
	msgs[1].msg_hdr.msg_iovlen = 1;

	uint32_t vlen = msgs.size();
	int flags = 0;
	assert_syscall_state(SYSCALL_SUCCESS,
	                     "sendmmsg (client)",
	                     syscall(__NR_sendmmsg, client_socket_fd, msgs.data(), vlen, flags),
	                     EQUAL,
	                     vlen);

	/* Cleaning phase */
	syscall(__NR_shutdown, server_socket_fd, 2);
	syscall(__NR_shutdown, client_socket_fd, 2);
	syscall(__NR_close, server_socket_fd);
	syscall(__NR_close, client_socket_fd);

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->disable_capture();

	for(const auto& m : msgs) {
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
		evt_test->assert_numeric_param(2, (int64_t)client_socket_fd);

		if(m.msg_len > DEFAULT_SNAPLEN) {
			/* Parameter 3: size (type: PT_UINT32) */
			evt_test->assert_numeric_param(3, LONG_MESSAGE_LEN);

			/* Parameter 4: data (type: PT_BYTEBUF) */
			evt_test->assert_bytebuf_param(4, LONG_MESSAGE, DEFAULT_SNAPLEN);
		} else {
			/* Parameter 3: size (type: PT_UINT32) */
			evt_test->assert_numeric_param(3, (uint32_t)m.msg_len);

			/* Parameter 4: data (type: PT_BYTEBUF) */
			evt_test->assert_bytebuf_param(4, SHORT_MESSAGE, (int32_t)m.msg_len);
		}

		/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
		evt_test->assert_tuple_inet6_param(5,
		                                   PPM_AF_INET6,
		                                   IPV6_CLIENT,
		                                   IPV6_SERVER,
		                                   IPV6_PORT_CLIENT_STRING,
		                                   IPV6_PORT_SERVER_STRING);
		/*=============================== ASSERT PARAMETERS  ===========================*/

		evt_test->assert_num_params_pushed(5);
	}
}
#endif

#include "../../event_class/event_class.h"

#ifdef __NR_sendmsg

#if defined(__NR_connect) && defined(__NR_socket) && defined(__NR_bind) && defined(__NR_listen) && \
        defined(__NR_close) && defined(__NR_setsockopt) && defined(__NR_shutdown)

/*=============================== TCP ===========================*/

TEST(SyscallExit, sendmsgX_ipv4_tcp_message_not_truncated_by_snaplen) {
	auto evt_test = get_syscall_event_test(__NR_sendmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_fd, server_fd;
	evt_test->client_to_server_ipv4_tcp(&client_fd,
	                                    &server_fd,
	                                    send_data{.syscall_num = __NR_sendmsg});

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

	/* Parameter 2: data (type: PT_BYTEBUF)*/
	evt_test->assert_bytebuf_param(2, SHORT_MESSAGE, SHORT_MESSAGE_LEN);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

TEST(SyscallExit, sendmsgX_ipv4_tcp_message_truncated_by_snaplen) {
	auto evt_test = get_syscall_event_test(__NR_sendmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_fd, server_fd;
	evt_test->client_to_server_ipv4_tcp(
	        &client_fd,
	        &server_fd,
	        send_data{.syscall_num = __NR_sendmsg, .greater_snaplen = true});

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

	/* Parameter 2: data (type: PT_BYTEBUF)*/
	evt_test->assert_bytebuf_param(2, LONG_MESSAGE, DEFAULT_SNAPLEN);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

TEST(SyscallExit, sendmsgX_ipv4_tcp_message_not_truncated_fullcapture_port) {
	auto evt_test = get_syscall_event_test(__NR_sendmsg, EXIT_EVENT);

	evt_test->set_do_dynamic_snaplen(true);

	// In sendmsg the missing one is the server port because it is the destination port.
	evt_test->set_fullcapture_port_range(IPV4_PORT_SERVER, IPV4_PORT_SERVER);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_fd, server_fd;
	evt_test->client_to_server_ipv4_tcp(
	        &client_fd,
	        &server_fd,
	        send_data{.syscall_num = __NR_sendmsg, .greater_snaplen = true});

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

	/* Parameter 2: data (type: PT_BYTEBUF)*/
	evt_test->assert_bytebuf_param(2, LONG_MESSAGE, LONG_MESSAGE_LEN);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

TEST(SyscallExit, sendmsgX_ipv6_tcp_message_not_truncated_fullcapture_port) {
	auto evt_test = get_syscall_event_test(__NR_sendmsg, EXIT_EVENT);

	evt_test->set_do_dynamic_snaplen(true);

	// In sendmsg the missing one is the server port because it is the destination port.
	evt_test->set_fullcapture_port_range(IPV6_PORT_SERVER, IPV6_PORT_SERVER);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_fd, server_fd;
	evt_test->client_to_server_ipv6_tcp(
	        &client_fd,
	        &server_fd,
	        send_data{.syscall_num = __NR_sendmsg, .greater_snaplen = true});

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

	/* Parameter 2: data (type: PT_BYTEBUF)*/
	evt_test->assert_bytebuf_param(2, LONG_MESSAGE, LONG_MESSAGE_LEN);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

TEST(SyscallExit, sendmsgX_ipv4_tcp_message_not_truncated_fullcapture_port_NULL_sockaddr) {
	auto evt_test = get_syscall_event_test(__NR_sendmsg, EXIT_EVENT);

	evt_test->set_do_dynamic_snaplen(true);

	evt_test->set_fullcapture_port_range(IPV4_PORT_SERVER, IPV4_PORT_SERVER);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_fd, server_fd;
	evt_test->client_to_server_ipv4_tcp(
	        &client_fd,
	        &server_fd,
	        send_data{.syscall_num = __NR_sendmsg, .greater_snaplen = true, .null_sockaddr = true});

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

	/* Parameter 2: data (type: PT_BYTEBUF)*/
	evt_test->assert_bytebuf_param(2, LONG_MESSAGE, LONG_MESSAGE_LEN);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

/*=============================== UDP ===========================*/

TEST(SyscallExit, sendmsgX_ipv4_udp_message_not_truncated_by_snaplen) {
	auto evt_test = get_syscall_event_test(__NR_sendmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_fd, server_fd;
	evt_test->client_to_server_ipv4_udp(&client_fd,
	                                    &server_fd,
	                                    send_data{.syscall_num = __NR_sendmsg});

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

	/* Parameter 2: data (type: PT_BYTEBUF)*/
	evt_test->assert_bytebuf_param(2, SHORT_MESSAGE, SHORT_MESSAGE_LEN);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

TEST(SyscallExit, sendmsgX_ipv4_udp_message_truncated_by_snaplen) {
	auto evt_test = get_syscall_event_test(__NR_sendmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_fd, server_fd;
	evt_test->client_to_server_ipv4_udp(
	        &client_fd,
	        &server_fd,
	        send_data{.syscall_num = __NR_sendmsg, .greater_snaplen = true});

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

	/* Parameter 2: data (type: PT_BYTEBUF)*/
	evt_test->assert_bytebuf_param(2, LONG_MESSAGE, DEFAULT_SNAPLEN);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

TEST(SyscallExit, sendmsgX_ipv4_udp_message_not_truncated_fullcapture_port) {
	auto evt_test = get_syscall_event_test(__NR_sendmsg, EXIT_EVENT);

	evt_test->set_do_dynamic_snaplen(true);

	evt_test->set_fullcapture_port_range(IPV4_PORT_SERVER, IPV4_PORT_SERVER);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_fd, server_fd;
	evt_test->client_to_server_ipv4_udp(
	        &client_fd,
	        &server_fd,
	        send_data{.syscall_num = __NR_sendmsg, .greater_snaplen = true});

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

	/* Parameter 2: data (type: PT_BYTEBUF)*/
	evt_test->assert_bytebuf_param(2, LONG_MESSAGE, LONG_MESSAGE_LEN);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

// We cannot call a sendmsg without a destination address in UDP. Errno: 89 err_message: Destination
// address required. TEST(SyscallExit,
// sendmsgX_ipv4_udp_message_not_truncated_fullcapture_port_NULL_sockaddr)

#endif

TEST(SyscallExit, sendmsgX_fail) {
	auto evt_test = get_syscall_event_test(__NR_sendmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t mock_fd = -1;
	struct msghdr send_msg = {};
	struct iovec iov[1] = {};
	memset(&send_msg, 0, sizeof(send_msg));
	memset(iov, 0, sizeof(iov));
	char sent_data_1[DEFAULT_SNAPLEN / 2] = "some-data";
	iov[0].iov_base = sent_data_1;
	iov[0].iov_len = sizeof(sent_data_1);
	send_msg.msg_iov = iov;
	send_msg.msg_iovlen = 1;
	uint32_t sendmsg_flags = 0;

	assert_syscall_state(SYSCALL_FAILURE,
	                     "sendmsg",
	                     syscall(__NR_sendmsg, mock_fd, &send_msg, sendmsg_flags));
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

	/* Parameter 2: data (type: PT_BYTEBUF)*/
	evt_test->assert_bytebuf_param(2, sent_data_1, DEFAULT_SNAPLEN / 2);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

TEST(SyscallExit, sendmsgX_null_iovec) {
	auto evt_test = get_syscall_event_test(__NR_sendmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t mock_fd = -1;
	struct msghdr send_msg = {};
	memset(&send_msg, 0, sizeof(send_msg));
	send_msg.msg_iov = NULL;
	/* here we pass a wrong `iovlen` to check the behavior */
	send_msg.msg_iovlen = 3;
	uint32_t sendmsg_flags = 0;

	assert_syscall_state(SYSCALL_FAILURE,
	                     "sendmsg",
	                     syscall(__NR_sendmsg, mock_fd, &send_msg, sendmsg_flags));
	int64_t errno_value = -errno;

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	if(evt_test->is_modern_bpf_engine()) {
		evt_test->assert_event_presence();
	} else {
		/* we need to rewrite the logic in old drivers to support this partial collection
		 * right now we drop the entire event.
		 */
		evt_test->assert_event_absence();
		GTEST_SKIP() << "[SENDMSG_X]: what we receive is correct but we need to reimplement it, "
		                "see the code"
		             << std::endl;
	}

	if(HasFatalFailure()) {
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

	evt_test->assert_num_params_pushed(2);
}

TEST(SyscallExit, sendmsgX_null_msghdr) {
	auto evt_test = get_syscall_event_test(__NR_sendmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t mock_fd = -1;
	struct msghdr* send_msg = NULL;
	uint32_t sendmsg_flags = 0;

	assert_syscall_state(SYSCALL_FAILURE,
	                     "sendmsg",
	                     syscall(__NR_sendmsg, mock_fd, send_msg, sendmsg_flags));
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

	/* Parameter 2: data (type: PT_BYTEBUF)*/
	evt_test->assert_empty_param(2);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

#endif /* __NR_sendmsg */

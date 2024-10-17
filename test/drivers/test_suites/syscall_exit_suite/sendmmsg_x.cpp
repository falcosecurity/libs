#include "../../event_class/event_class.h"
#include "test/drivers/event_class/network_utils.h"

#ifdef __NR_sendmmsg

#if defined(__NR_connect) && defined(__NR_socket) && defined(__NR_bind) && defined(__NR_listen) && \
        defined(__NR_close) && defined(__NR_setsockopt) && defined(__NR_shutdown)

/* By default `snaplen` is 80 bytes.
 * No `snaplen` because here we don't hit the 80 bytes so we don't have to truncate the message.
 */
TEST(SyscallExit, sendmmsgXNoSnaplen) {
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
	static char sent_data_1[FIRST_MESSAGE_LEN] = "hey! there is a first message here.";
	static char sent_data_2[SECOND_MESSAGE_LEN] = "hey! there is a second message here.";
	iov[0].iov_base = sent_data_1;
	iov[0].iov_len = sizeof(sent_data_1);
	iov[1].iov_base = sent_data_2;
	iov[1].iov_len = sizeof(sent_data_2);

	struct mmsghdr msg = {};
	msg.msg_hdr.msg_name = (sockaddr*)&server_addr;
	msg.msg_hdr.msg_namelen = sizeof(server_addr);
	msg.msg_hdr.msg_iov = iov.data();
	msg.msg_hdr.msg_iovlen = iov.size();

	uint32_t vlen = 1;
	int flags = 0;
	assert_syscall_state(SYSCALL_SUCCESS,
	                     "sendmmsg (client)",
	                     syscall(__NR_sendmmsg, client_socket_fd, &msg, vlen, flags),
	                     EQUAL,
	                     vlen);

	/* Cleaning phase */
	syscall(__NR_shutdown, server_socket_fd, 2);
	syscall(__NR_shutdown, client_socket_fd, 2);
	syscall(__NR_close, server_socket_fd);
	syscall(__NR_close, client_socket_fd);

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
	evt_test->assert_numeric_param(1, (int64_t)msg.msg_len);

	/* Parameter 2: fd (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)client_socket_fd);

	/* Parameter 3: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(3, (uint32_t)msg.msg_len);

	/* Parameter 4: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(4, NO_SNAPLEN_MESSAGE, (int32_t)msg.msg_len);

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

/* Here we need to truncate our message since it is greater than `snaplen` */
TEST(SyscallExit, sendmmsgXSnaplen) {
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

	/* Send a message to the server */
	std::array<struct iovec, 3> iov = {};
	static char sent_data_1[FIRST_MESSAGE_LEN] = "hey! there is a first message here.";
	static char sent_data_2[SECOND_MESSAGE_LEN] = "hey! there is a second message here.";
	static char sent_data_3[THIRD_MESSAGE_LEN] = "hey! there is a third message here.";
	iov[0].iov_base = sent_data_1;
	iov[0].iov_len = sizeof(sent_data_1);
	iov[1].iov_base = sent_data_2;
	iov[1].iov_len = sizeof(sent_data_2);
	iov[2].iov_base = sent_data_3;
	iov[2].iov_len = sizeof(sent_data_3);

	struct mmsghdr msg = {};
	msg.msg_hdr.msg_name = (sockaddr*)&server_addr;
	msg.msg_hdr.msg_namelen = sizeof(server_addr);
	msg.msg_hdr.msg_iov = iov.data();
	msg.msg_hdr.msg_iovlen = iov.size();

	uint32_t vlen = 1;
	int flags = 0;
	assert_syscall_state(SYSCALL_SUCCESS,
	                     "sendmmsg (client)",
	                     syscall(__NR_sendmmsg, client_socket_fd, &msg, vlen, flags),
	                     EQUAL,
	                     vlen);

	/* Cleaning phase */
	syscall(__NR_shutdown, server_socket_fd, 2);
	syscall(__NR_shutdown, client_socket_fd, 2);
	syscall(__NR_close, server_socket_fd);
	syscall(__NR_close, client_socket_fd);

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
	evt_test->assert_numeric_param(1, (int64_t)msg.msg_len);

	/* Parameter 2: fd (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)client_socket_fd);

	/* Parameter 3: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(3, (uint32_t)FULL_MESSAGE_LEN);

	/* Parameter 4: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(4, FULL_MESSAGE, DEFAULT_SNAPLEN);

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

#endif

TEST(SyscallExit, sendmmsgXFail) {
	auto evt_test = get_syscall_event_test(__NR_sendmmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t mock_fd = -1;
	std::array<struct iovec, 1> iov = {};
	static char sent_data_1[DEFAULT_SNAPLEN / 2] = "some-data";
	iov[0].iov_base = sent_data_1;
	iov[0].iov_len = sizeof(sent_data_1);

	struct mmsghdr msg = {};
	msg.msg_hdr.msg_iov = iov.data();
	msg.msg_hdr.msg_iovlen = iov.size();

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
	evt_test->assert_empty_param(2);

	/* Parameter 3: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(3, (uint32_t)0);

	/* Parameter 4: data (type: PT_BYTEBUF) */
	evt_test->assert_empty_param(4);

	/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
	evt_test->assert_empty_param(5);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

TEST(SyscallExit, sendmmsgXNullIovec) {
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
	evt_test->assert_empty_param(2);

	/* Parameter 3: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(3, (uint32_t)0);

	/* Parameter 4: data (type: PT_BYTEBUF) */
	evt_test->assert_empty_param(4);

	/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
	evt_test->assert_empty_param(5);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

TEST(SyscallExit, sendmmsgXNullMmsghdr) {
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
	evt_test->assert_empty_param(2);

	/* Parameter 3: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(3, (uint32_t)0);

	/* Parameter 4: data (type: PT_BYTEBUF) */
	evt_test->assert_empty_param(4);

	/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
	evt_test->assert_empty_param(5);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

TEST(SyscallExit, sendmmsgMultipleMessages) {
	auto evt_test = get_syscall_event_test(__NR_sendmmsg, EXIT_EVENT);

	if(!evt_test->is_modern_bpf_engine()) {
		GTEST_SKIP() << (evt_test->is_bpf_engine() ? "eBPF " : "kmod ")
		             << "doesn't support multiple events";
	}

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

	static char sent_data_1[FIRST_MESSAGE_LEN] = "hey! there is a first message here.";
	static char sent_data_2[SECOND_MESSAGE_LEN] = "hey! there is a second message here.";
	static char sent_data_3[THIRD_MESSAGE_LEN] = "hey! there is a third message here.";

	std::array<struct iovec, 2> iov1 = {};
	iov1[0].iov_base = sent_data_1;
	iov1[0].iov_len = sizeof(sent_data_1);
	iov1[1].iov_base = sent_data_2;
	iov1[1].iov_len = sizeof(sent_data_2);

	std::array<struct iovec, 3> iov2 = {};
	iov2[0].iov_base = sent_data_1;
	iov2[0].iov_len = sizeof(sent_data_1);
	iov2[1].iov_base = sent_data_2;
	iov2[1].iov_len = sizeof(sent_data_2);
	iov2[2].iov_base = sent_data_3;
	iov2[2].iov_len = sizeof(sent_data_3);

	std::array<struct mmsghdr, 2> msgs = {};
	for(auto& m : msgs) {
		m.msg_hdr.msg_name = (sockaddr*)&server_addr;
		m.msg_hdr.msg_namelen = sizeof(server_addr);
	}
	msgs[0].msg_hdr.msg_iov = iov1.data();
	msgs[0].msg_hdr.msg_iovlen = iov1.size();
	msgs[1].msg_hdr.msg_iov = iov2.data();
	msgs[1].msg_hdr.msg_iovlen = iov2.size();

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
			evt_test->assert_numeric_param(3, FULL_MESSAGE_LEN);

			/* Parameter 4: data (type: PT_BYTEBUF) */
			evt_test->assert_bytebuf_param(4, FULL_MESSAGE, DEFAULT_SNAPLEN);
		} else {
			/* Parameter 3: size (type: PT_UINT32) */
			evt_test->assert_numeric_param(3, (uint32_t)m.msg_len);

			/* Parameter 4: data (type: PT_BYTEBUF) */
			evt_test->assert_bytebuf_param(4, NO_SNAPLEN_MESSAGE, (int32_t)m.msg_len);
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
#endif

#include "../../event_class/event_class.h"

#ifdef __NR_sendmsg

#if defined(__NR_connect) && defined(__NR_socket) && defined(__NR_bind) && defined(__NR_listen) && defined(__NR_close) && defined(__NR_setsockopt) && defined(__NR_shutdown)

/* By default `snaplen` is 80 bytes.
 * No `snaplen` because here we don't hit the 80 bytes so we don't have to truncate the message.
 */
TEST(SyscallExit, sendmsgX_no_snaplen)
{
	auto evt_test = get_syscall_event_test(__NR_sendmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_socket_fd = 0;
	int32_t server_socket_fd = 0;
	sockaddr_in client_addr = {0};
	sockaddr_in server_addr = {0};
	evt_test->connect_ipv4_client_to_server(&client_socket_fd, &client_addr, &server_socket_fd, &server_addr);

	/* Send a message to the server */
	struct msghdr send_msg;
	struct iovec iov[2];
	memset(&send_msg, 0, sizeof(send_msg));
	memset(iov, 0, sizeof(iov));
	send_msg.msg_name = (sockaddr*)&server_addr;
	send_msg.msg_namelen = sizeof(server_addr);
	char sent_data_1[FIRST_MESSAGE_LEN] = "hey! there is a first message here.";
	char sent_data_2[SECOND_MESSAGE_LEN] = "hey! there is a second message here.";
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
	evt_test->assert_bytebuf_param(2, NO_SNAPLEN_MESSAGE, sent_bytes);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

/* Here we need to truncate our message since it is greater than `snaplen` */
TEST(SyscallExit, sendmsgX_snaplen)
{
	auto evt_test = get_syscall_event_test(__NR_sendmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_socket_fd = 0;
	int32_t server_socket_fd = 0;
	sockaddr_in client_addr = {0};
	sockaddr_in server_addr = {0};
	evt_test->connect_ipv4_client_to_server(&client_socket_fd, &client_addr, &server_socket_fd, &server_addr);

	/* Send a message to the server */
	struct msghdr send_msg;
	struct iovec iov[3];
	memset(&send_msg, 0, sizeof(send_msg));
	memset(iov, 0, sizeof(iov));
	send_msg.msg_name = (sockaddr*)&server_addr;
	send_msg.msg_namelen = sizeof(server_addr);
	char sent_data_1[FIRST_MESSAGE_LEN] = "hey! there is a first message here.";
	char sent_data_2[SECOND_MESSAGE_LEN] = "hey! there is a second message here.";
	char sent_data_3[THIRD_MESSAGE_LEN] = "hey! there is a third message here.";
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
	evt_test->assert_bytebuf_param(2, FULL_MESSAGE, DEFAULT_SNAPLEN);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}
#endif

TEST(SyscallExit, sendmsgX_fail)
{
	auto evt_test = get_syscall_event_test(__NR_sendmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t mock_fd = -1;
	struct msghdr send_msg = {0};
	struct iovec iov[1] = {0};
	memset(&send_msg, 0, sizeof(send_msg));
	memset(iov, 0, sizeof(iov));
	char sent_data_1[DEFAULT_SNAPLEN / 2] = "some-data";
	iov[0].iov_base = sent_data_1;
	iov[0].iov_len = sizeof(sent_data_1);
	send_msg.msg_iov = iov;
	/* here we pass a wrong `iovlen` to check the behavior */
	send_msg.msg_iovlen = 3;
	uint32_t sendmsg_flags = 0;

	assert_syscall_state(SYSCALL_FAILURE, "sendmsg", syscall(__NR_sendmsg, mock_fd, &send_msg, sendmsg_flags));
	int64_t errno_value = -errno;

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

#ifdef __s390x__
	/* For some reason this test is successful also with old bpf probe on s390x */
	if(evt_test->is_modern_bpf_engine()	|| evt_test->is_bpf_engine())
#else
	if(evt_test->is_modern_bpf_engine())
#endif
	{
		evt_test->assert_event_presence();
	}
	else
	{
		/* we need to rewrite the logic in old drivers to support this partial collection
		 * right now we drop the entire event.
		 */
		evt_test->assert_event_absence();
		GTEST_SKIP() << "[SENDMSG_X]: what we receive is correct but we need to reimplement it, see the code" << std::endl;
	}

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
	evt_test->assert_bytebuf_param(2, sent_data_1, DEFAULT_SNAPLEN / 2);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

TEST(SyscallExit, sendmsgX_null_iovec)
{
	auto evt_test = get_syscall_event_test(__NR_sendmsg, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t mock_fd = -1;
	struct msghdr send_msg = {0};
	memset(&send_msg, 0, sizeof(send_msg));
	send_msg.msg_iov = NULL;
	/* here we pass a wrong `iovlen` to check the behavior */
	send_msg.msg_iovlen = 3;
	uint32_t sendmsg_flags = 0;

	assert_syscall_state(SYSCALL_FAILURE, "sendmsg", syscall(__NR_sendmsg, mock_fd, &send_msg, sendmsg_flags));
	int64_t errno_value = -errno;

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	if(evt_test->is_modern_bpf_engine())
	{
		evt_test->assert_event_presence();
	}
	else
	{
		/* we need to rewrite the logic in old drivers to support this partial collection
		 * right now we drop the entire event.
		 */
		evt_test->assert_event_absence();
		GTEST_SKIP() << "[SENDMSG_X]: what we receive is correct but we need to reimplement it, see the code" << std::endl;
	}

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

	evt_test->assert_num_params_pushed(2);
}

TEST(SyscallExit, sendmsgX_null_msghdr)
{
	auto evt_test = get_syscall_event_test(__NR_sendmsg, EXIT_EVENT);

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

	evt_test->assert_num_params_pushed(2);
}

#endif /* __NR_sendmsg */

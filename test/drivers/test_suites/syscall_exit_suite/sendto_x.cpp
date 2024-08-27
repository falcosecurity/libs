#include "../../event_class/event_class.h"

#ifdef __NR_sendto

#if defined(__NR_connect) && defined(__NR_socket) && defined(__NR_bind) && defined(__NR_listen) && defined(__NR_close) && defined(__NR_setsockopt) && defined(__NR_shutdown)

/* By default `snaplen` is 80 bytes.
 * No `snaplen` because here we don't hit the 80 bytes so we don't have to truncate the message.
 */
TEST(SyscallExit, sendtoX_no_snaplen)
{
	auto evt_test = get_syscall_event_test(__NR_sendto, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_socket_fd = 0;
	int32_t server_socket_fd = 0;
	sockaddr_in client_addr = {};
	sockaddr_in server_addr = {};
	evt_test->connect_ipv4_client_to_server(&client_socket_fd, &client_addr, &server_socket_fd, &server_addr);

	/* Send a message to the server */
	char sent_data[NO_SNAPLEN_MESSAGE_LEN] = NO_SNAPLEN_MESSAGE;
	uint32_t sendto_flags = 0;
	int64_t sent_bytes = syscall(__NR_sendto, client_socket_fd, sent_data, sizeof(sent_data), sendto_flags, (sockaddr*)&server_addr, sizeof(server_addr));
	assert_syscall_state(SYSCALL_SUCCESS, "sendto (client)", sent_bytes, NOT_EQUAL, -1);

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
TEST(SyscallExit, sendtoX_snaplen)
{
	auto evt_test = get_syscall_event_test(__NR_sendto, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t client_socket_fd = 0;
	int32_t server_socket_fd = 0;
	sockaddr_in client_addr = {};
	sockaddr_in server_addr = {};
	evt_test->connect_ipv4_client_to_server(&client_socket_fd, &client_addr, &server_socket_fd, &server_addr);

	/* Send a message to the server */
	char sent_data[FULL_MESSAGE_LEN] = FULL_MESSAGE;
	uint32_t sendto_flags = 0;
	int64_t sent_bytes = syscall(__NR_sendto, client_socket_fd, sent_data, sizeof(sent_data), sendto_flags, (sockaddr*)&server_addr, sizeof(server_addr));
	assert_syscall_state(SYSCALL_SUCCESS, "sendto (client)", sent_bytes, NOT_EQUAL, -1);

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

TEST(SyscallExit, sendtoX_fail)
{
	auto evt_test = get_syscall_event_test(__NR_sendto, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t mock_fd = -1;
	char sent_data[DEFAULT_SNAPLEN / 2] = "some-data";
	size_t len = DEFAULT_SNAPLEN / 2;
	uint32_t sendto_flags = 0;
	struct sockaddr* dest_addr = NULL;
	socklen_t addrlen = 0;

	assert_syscall_state(SYSCALL_FAILURE, "sendto", syscall(__NR_sendto, mock_fd, sent_data, len, sendto_flags, dest_addr, addrlen));
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
	evt_test->assert_bytebuf_param(2, sent_data, DEFAULT_SNAPLEN / 2);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

TEST(SyscallExit, sendtoX_empty)
{
	auto evt_test = get_syscall_event_test(__NR_sendto, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t mock_fd = -1;
	char* sent_data = NULL;
	size_t len = 0;
	uint32_t sendto_flags = 0;
	struct sockaddr* dest_addr = NULL;
	socklen_t addrlen = 0;

	assert_syscall_state(SYSCALL_FAILURE, "sendto", syscall(__NR_sendto, mock_fd, sent_data, len, sendto_flags, dest_addr, addrlen));
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

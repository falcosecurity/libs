#include "../../event_class/event_class.h"

#ifdef __NR_read

#if defined(__NR_close) && defined(__NR_open)

TEST(SyscallExit, readX_no_snaplen)
{
	auto evt_test = get_syscall_event_test(__NR_read, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Open /dev/urandom for reading */
	int fd = syscall(__NR_open, "/dev/urandom", O_RDONLY);
	assert_syscall_state(SYSCALL_SUCCESS, "open", fd, NOT_EQUAL, -1);

	/* Read data from /dev/urandom */
	const unsigned data_len = DEFAULT_SNAPLEN / 2;
	char buf[data_len];
	ssize_t read_bytes = syscall(__NR_read, fd, (void *)buf, data_len);
	assert_syscall_state(SYSCALL_SUCCESS, "read", read_bytes, NOT_EQUAL, -1);

	/* Close /dev/urandom fd */
	syscall(__NR_close, fd);

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
	evt_test->assert_numeric_param(1, (int64_t)read_bytes);

	/* Parameter 2: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(2, buf, read_bytes);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

TEST(SyscallExit, readX_snaplen)
{
	auto evt_test = get_syscall_event_test(__NR_read, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Open /dev/urandom for reading */
	int fd = syscall(__NR_open, "/dev/urandom", O_RDONLY);
	assert_syscall_state(SYSCALL_SUCCESS, "open", fd, NOT_EQUAL, -1);

	/* Read data from /dev/urandom */
	const unsigned data_len = DEFAULT_SNAPLEN * 2;
	char buf[data_len];
	ssize_t read_bytes = syscall(__NR_read, fd, (void *)buf, data_len);
	assert_syscall_state(SYSCALL_SUCCESS, "read", read_bytes, NOT_EQUAL, -1);

	/* Close /dev/urandom fd */
	syscall(__NR_close, fd);

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
	evt_test->assert_numeric_param(1, (int64_t)read_bytes);

	/* Parameter 2: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(2, buf, DEFAULT_SNAPLEN);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

TEST(SyscallExit, readXfail)
{
	auto evt_test = get_syscall_event_test(__NR_read, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Read data from an invalid fd */
	const unsigned data_len = 64;
	char buf[data_len];
	ssize_t read_bytes = syscall(__NR_read, -1, (void *)buf, data_len);
	int errno_value = -errno;
	assert_syscall_state(SYSCALL_FAILURE, "read", read_bytes);

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

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

TEST(SyscallExit, readX_ipv4_tcp_message_truncated_by_snaplen)
{
	auto evt_test = get_syscall_event_test(__NR_read, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->client_to_server(send_data{.syscall_num = __NR_sendto, .greater_snaplen = true},
					receive_data{.syscall_num = __NR_read}, protocol_L3::IPv4, protocol_L4::TCP);

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
	evt_test->assert_bytebuf_param(2, LONG_MESSAGE, DEFAULT_SNAPLEN);
	

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

TEST(SyscallExit, readX_ipv4_tcp_message_not_truncated_fullcapture_port)
{
	auto evt_test = get_syscall_event_test(__NR_read, EXIT_EVENT);

	evt_test->set_do_dynamic_snaplen(true);

	// Now the client port is in the range so we should see the full message not truncated by the snaplen.
	evt_test->set_fullcapture_port_range(IPV4_PORT_CLIENT, IPV4_PORT_CLIENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->client_to_server(send_data{.syscall_num = __NR_sendto, .greater_snaplen = true},
					receive_data{.syscall_num = __NR_read}, protocol_L3::IPv4, protocol_L4::TCP);

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->set_do_dynamic_snaplen(false);

	evt_test->assert_event_presence();

	/* we need to clean the values after we read our event because the kernel module
	 * flushes the ring buffers when we change this config.
	 */
	evt_test->set_fullcapture_port_range(0, 0);

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
	evt_test->assert_bytebuf_param(2, LONG_MESSAGE, MAX_RECV_BUF_SIZE);
	
	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

TEST(SyscallExit, readX_ipv4_udp_message_truncated_by_snaplen)
{
	auto evt_test = get_syscall_event_test(__NR_read, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->client_to_server(send_data{.syscall_num = __NR_sendto, .greater_snaplen = true},
					receive_data{.syscall_num = __NR_read}, protocol_L3::IPv4, protocol_L4::UDP);

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
	evt_test->assert_bytebuf_param(2, LONG_MESSAGE, DEFAULT_SNAPLEN);
	
	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

TEST(SyscallExit, readX_ipv4_udp_message_truncated_fullcapture_client_port)
{
	auto evt_test = get_syscall_event_test(__NR_read, EXIT_EVENT);

	evt_test->set_do_dynamic_snaplen(true);

	evt_test->set_fullcapture_port_range(IPV4_PORT_CLIENT, IPV4_PORT_CLIENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->client_to_server(send_data{.syscall_num = __NR_sendto, .greater_snaplen = true},
					receive_data{.syscall_num = __NR_read}, protocol_L3::IPv4, protocol_L4::UDP);

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->set_do_dynamic_snaplen(false);

	evt_test->assert_event_presence();

	/* we need to clean the values after we read our event because the kernel module
	 * flushes the ring buffers when we change this config.
	 */
	evt_test->set_fullcapture_port_range(0, 0);

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
	// We cannot retrieve the client port and so the FULLCAPTURE_PORT_RANGE logic doesn't increase the snaplen.
	evt_test->assert_bytebuf_param(2, LONG_MESSAGE, DEFAULT_SNAPLEN);
	
	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

TEST(SyscallExit, readX_ipv4_udp_message_not_truncated_fullcapture_server_port)
{
	auto evt_test = get_syscall_event_test(__NR_read, EXIT_EVENT);

	evt_test->set_do_dynamic_snaplen(true);

	// In this case we should be able to retrieve the server port from the kernel socket because it is the local port
	// We are receiving on the server.
	evt_test->set_fullcapture_port_range(IPV4_PORT_SERVER, IPV4_PORT_SERVER);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->client_to_server(send_data{.syscall_num = __NR_sendto, .greater_snaplen = true},
					receive_data{.syscall_num = __NR_read}, protocol_L3::IPv4, protocol_L4::UDP);

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->set_do_dynamic_snaplen(false);

	evt_test->assert_event_presence();

	/* we need to clean the values after we read our event because the kernel module
	 * flushes the ring buffers when we change this config.
	 */
	evt_test->set_fullcapture_port_range(0, 0);

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
	evt_test->assert_bytebuf_param(2, LONG_MESSAGE, MAX_RECV_BUF_SIZE);
	
	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

#endif
#endif

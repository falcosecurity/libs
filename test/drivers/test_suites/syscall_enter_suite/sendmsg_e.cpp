#include "../../event_class/event_class.h"

#if defined(__NR_connect) && defined(__NR_socket) && defined(__NR_bind) && defined(__NR_listen) &&                     \
	defined(__NR_close) && defined(__NR_setsockopt) && defined(__NR_shutdown) && defined(__NR_sendmsg)

/*=============================== TCP ===========================*/

TEST(SyscallEnter, sendmsgE_ipv4_tcp)
{
	auto evt_test = get_syscall_event_test(__NR_sendmsg, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->client_to_server(send_data{.syscall_num = __NR_sendmsg}, receive_data{.skip_recv_phase = true},
					protocol_L3::IPv4, protocol_L4::TCP);

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

	/* Parameter 2: size (type: PT_UINT32)*/
	evt_test->assert_numeric_param(2, (uint32_t)SHORT_MESSAGE_LEN);

	/* Parameter 3: tuple (type: PT_SOCKTUPLE)*/
	evt_test->assert_tuple_inet_param(3, PPM_AF_INET, IPV4_CLIENT, IPV4_SERVER, IPV4_PORT_CLIENT_STRING,
					  IPV4_PORT_SERVER_STRING);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}

TEST(SyscallEnter, sendmsgE_ipv4_tcp_NULL_sockaddr)
{
	auto evt_test = get_syscall_event_test(__NR_sendmsg, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->client_to_server(send_data{.syscall_num = __NR_sendmsg, .null_sockaddr = true},
					receive_data{.skip_recv_phase = true}, protocol_L3::IPv4, protocol_L4::TCP);

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

	/* Parameter 2: size (type: PT_UINT32)*/
	evt_test->assert_numeric_param(2, (uint32_t)SHORT_MESSAGE_LEN);

	/* Parameter 3: tuple (type: PT_SOCKTUPLE)*/
	if(evt_test->is_modern_bpf_engine())
	{
		// We can recover the tuple even without the userspace socaddr
		evt_test->assert_tuple_inet_param(3, PPM_AF_INET, IPV4_CLIENT, IPV4_SERVER, IPV4_PORT_CLIENT_STRING,
						  IPV4_PORT_SERVER_STRING);
	}
	else
	{
		// todo!: We are reading some random stuff, because we don't use kernel info
		GTEST_SKIP() << "We obtain a wrong tuple because we don't use the kernel info";
	}

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}

/*=============================== UDP ===========================*/

TEST(SyscallEnter, sendmsgE_ipv4_udp)
{
	auto evt_test = get_syscall_event_test(__NR_sendmsg, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->client_to_server(send_data{.syscall_num = __NR_sendmsg}, receive_data{.skip_recv_phase = true},
					protocol_L3::IPv4, protocol_L4::UDP);

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

	/* Parameter 2: size (type: PT_UINT32)*/
	evt_test->assert_numeric_param(2, (uint32_t)SHORT_MESSAGE_LEN);

	/* Parameter 3: tuple (type: PT_SOCKTUPLE)*/
	evt_test->assert_tuple_inet_param(3, PPM_AF_INET, IPV4_CLIENT, IPV4_SERVER, IPV4_PORT_CLIENT_STRING,
					  IPV4_PORT_SERVER_STRING);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}

// We cannot call a sendmsg without a destination address in UDP. Errno: 89 err_message: Destination address required
// TEST(SyscallEnter, sendmsgE_ipv4_udp_NULL_sockaddr)

TEST(SyscallEnter, sendmsgE_fail)
{
	auto evt_test = get_syscall_event_test(__NR_sendmsg, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t mock_fd = -12;
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

	assert_syscall_state(SYSCALL_FAILURE, "sendmsg", syscall(__NR_sendmsg, mock_fd, &send_msg, sendmsg_flags));

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

	/* Parameter 1: fd (type: PT_FD) */
	evt_test->assert_numeric_param(1, (int64_t)mock_fd);

	/* Parameter 2: size (type: PT_UINT32)*/
	evt_test->assert_numeric_param(2, (uint32_t)sizeof(sent_data_1));

	/* Parameter 3: tuple (type: PT_SOCKTUPLE)*/
	evt_test->assert_empty_param(3);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}

#endif

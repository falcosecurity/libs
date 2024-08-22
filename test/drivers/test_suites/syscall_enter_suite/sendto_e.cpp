#include "../../event_class/event_class.h"

#if defined(__NR_connect) && defined(__NR_socket) && defined(__NR_bind) && defined(__NR_listen) &&                     \
	defined(__NR_close) && defined(__NR_setsockopt) && defined(__NR_shutdown) && defined(__NR_sendto)

/*=============================== TCP ===========================*/

TEST(SyscallEnter, sendtoE_ipv4_tcp)
{
	auto evt_test = get_syscall_event_test(__NR_sendto, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->client_to_server(send_data{.syscall_num = __NR_sendto}, receive_data{.skip_recv_phase = true},
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

TEST(SyscallEnter, sendtoE_ipv4_tcp_NULL_sockaddr)
{
	auto evt_test = get_syscall_event_test(__NR_sendto, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->client_to_server(send_data{.syscall_num = __NR_sendto, .null_sockaddr = true},
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

TEST(SyscallEnter, sendtoE_ipv4_udp)
{
	auto evt_test = get_syscall_event_test(__NR_sendto, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->client_to_server(send_data{.syscall_num = __NR_sendto}, receive_data{.skip_recv_phase = true},
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

// We cannot call a sendto without a destination address in UDP. Errno: 89 err_message: Destination address required
// TEST(SyscallEnter, sendtoE_ipv4_udp_NULL_sockaddr)

TEST(SyscallEnter, sendtoE_fail)
{
	auto evt_test = get_syscall_event_test(__NR_sendto, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t mock_fd = -12;
	size_t len = DEFAULT_SNAPLEN / 2; // random value
	uint32_t sendto_flags = 0;
	struct sockaddr* dest_addr = NULL;
	socklen_t addrlen = 0;

	assert_syscall_state(SYSCALL_FAILURE, "sendto",
			     syscall(__NR_sendto, mock_fd, NULL, len, sendto_flags, dest_addr, addrlen));

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
	evt_test->assert_numeric_param(2, (uint32_t)len);

	/* Parameter 3: tuple (type: PT_SOCKTUPLE)*/
	evt_test->assert_empty_param(3);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}
#endif

#include "../../event_class/event_class.h"

#if defined(__NR_connect)

TEST(SyscallEnter, connectE_INET)
{
	auto evt_test = get_syscall_event_test(__NR_connect, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t mock_fd = -1;
	sockaddr_in server_addr;
	evt_test->server_fill_sockaddr_in(&server_addr);
	assert_syscall_state(SYSCALL_FAILURE, "connect", syscall(__NR_connect, mock_fd, (sockaddr*)&server_addr, sizeof(server_addr)));

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

	/* Parameter 2: addr (type: PT_SOCKADDR)*/
	/* Modern BPF returns addr_info even if the syscall fails other drivers return an empty param. */
	if(evt_test->is_modern_bpf_engine())
	{
		evt_test->assert_addr_info_inet_param(2, PPM_AF_INET, IPV4_SERVER, IPV4_PORT_SERVER_STRING);
	}
	else
	{
		evt_test->assert_empty_param(2);
		evt_test->assert_num_params_pushed(2);
		GTEST_SKIP() << "[CONNECT_E]: what we receive is correct but we need to reimplement it, see the code" << std::endl;
	}

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

TEST(SyscallEnter, connectE_INET6)
{
	auto evt_test = get_syscall_event_test(__NR_connect, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t mock_fd = -1;
	sockaddr_in6 server_addr;
	evt_test->server_fill_sockaddr_in6(&server_addr);
	assert_syscall_state(SYSCALL_FAILURE, "connect", syscall(__NR_connect, mock_fd, (sockaddr*)&server_addr, sizeof(server_addr)));

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

	/* Parameter 2: addr (type: PT_SOCKADDR)*/
	/* Modern BPF returns addr_info even if the syscall fails other drivers return an empty param. */
	if(evt_test->is_modern_bpf_engine())
	{
		evt_test->assert_addr_info_inet6_param(2, PPM_AF_INET6, IPV6_SERVER, IPV6_PORT_SERVER_STRING);
	}
	else
	{
		evt_test->assert_empty_param(2);
		evt_test->assert_num_params_pushed(2);
		GTEST_SKIP() << "[CONNECT_E]: what we receive is correct but we need to reimplement it, see the code" << std::endl;
	}

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

TEST(SyscallEnter, connectE_UNIX)
{
	auto evt_test = get_syscall_event_test(__NR_connect, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	/* BPF-side, we read the path until we face a `\0` or until we reach
	 * the maximum length (`MAX_SUN_PATH`).
	 */
	int32_t mock_fd = -1;
	sockaddr_un server_addr;
	evt_test->server_fill_sockaddr_un(&server_addr);
	assert_syscall_state(SYSCALL_FAILURE, "connect", syscall(__NR_connect, mock_fd, (sockaddr*)&server_addr, sizeof(server_addr)));

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

	/* Parameter 2: addr (type: PT_SOCKADDR)*/
	/* Modern BPF returns addr_info even if the syscall fails other drivers return an empty param. */
	if(evt_test->is_modern_bpf_engine())
	{
		evt_test->assert_addr_info_unix_param(2, PPM_AF_UNIX, UNIX_SERVER);
	}
	else
	{
		evt_test->assert_empty_param(2);
		evt_test->assert_num_params_pushed(2);
		GTEST_SKIP() << "[CONNECT_E]: what we receive is correct but we need to reimplement it, see the code" << std::endl;
	}

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

/* This is 109 chars long, so no null terminator will be put inside the `sun_path` during the socket call.
 * The BPF prog can read at most `108` chars so instead of the `*`, it will put the `\0`.
 */
#define UNIX_LONG_PATH "/unix_socket/test/too_long/too_long/too_long/too_long/unix_socket/test/too_long/too_long/too_long/too_longgg*"
#define EXPECTED_UNIX_LONG_PATH "/unix_socket/test/too_long/too_long/too_long/too_long/unix_socket/test/too_long/too_long/too_long/too_longgg"

TEST(SyscallEnter, connectE_UNIX_max_path)
{
	auto evt_test = get_syscall_event_test(__NR_connect, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	/* The unix socket pathname has the maximum length so there is
	 * no null terminator `\0`. We want to see if BPF can manage this case by putting
	 * also the terminator `\0` at the end.
	 */

	int32_t mock_fd = -1;
	sockaddr_un server_addr;
	evt_test->server_fill_sockaddr_un(&server_addr, UNIX_LONG_PATH);
	assert_syscall_state(SYSCALL_FAILURE, "connect", syscall(__NR_connect, mock_fd, (sockaddr*)&server_addr, sizeof(server_addr)));

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

	/* Parameter 2: addr (type: PT_SOCKADDR)*/
	/* Modern BPF returns addr_info even if the syscall fails other drivers return an empty param. */
	if(evt_test->is_modern_bpf_engine())
	{
		evt_test->assert_addr_info_unix_param(2, PPM_AF_UNIX, EXPECTED_UNIX_LONG_PATH);
	}
	else
	{
		evt_test->assert_empty_param(2);
		evt_test->assert_num_params_pushed(2);
		GTEST_SKIP() << "[CONNECT_E]: what we receive is correct but we need to reimplement it, see the code" << std::endl;
	}

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

TEST(SyscallEnter, connectE_null_sockaddr)
{
	auto evt_test = get_syscall_event_test(__NR_connect, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	/* We pass an invalid socket `fd` so the `connect` must fail.
	 * The invalid socket fd, in this case, is negative so the `sockaddr` param will be empty.
	 */
	int32_t mock_fd = -1;
	sockaddr* addr = NULL;
	socklen_t addrlen = 0;
	assert_syscall_state(SYSCALL_FAILURE, "connect", syscall(__NR_connect, mock_fd, addr, addrlen));

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

	/* Parameter 2: addr (type: PT_SOCKADDR)*/
	/* Since the pointer to the `sockaddr` is `NULL` we expect an empty param here. */
	evt_test->assert_empty_param(2);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}
#endif

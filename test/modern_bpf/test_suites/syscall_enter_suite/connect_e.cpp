#include "../../event_class/event_class.h"

#if defined(__NR_connect)

#include <netdb.h>
#include <sys/un.h>

TEST(SyscallEnter, connectE_INET)
{
	auto evt_test = new event_test(__NR_connect, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	struct sockaddr_in server_addr;
	bzero(&server_addr, sizeof(server_addr));

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(IPV4_PORT_SERVER);

	/// TODO: this is not a syscall probably we need to change the name of the helper
	/// in something more generic...
	assert_syscall_state(SYSCALL_SUCCESS, "inet_pton", inet_pton(AF_INET, IPV4_SERVER, &server_addr.sin_addr), NOT_EQUAL, -1);
	/*  We pass an invalid socket fd so the `connect` must fail. */
	int32_t mock_fd = 5;
	assert_syscall_state(SYSCALL_FAILURE, "connect", syscall(__NR_connect, mock_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)));

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
	evt_test->assert_addr_info_inet_param(2, PPM_AF_INET, IPV4_SERVER, IPV4_PORT_SERVER_STRING);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

TEST(SyscallEnter, connectE_INET6)
{
	auto evt_test = new event_test(__NR_connect, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	struct sockaddr_in6 server_addr;
	bzero(&server_addr, sizeof(server_addr));

	server_addr.sin6_family = AF_INET6;
	server_addr.sin6_port = htons(IPV6_PORT_SERVER);

	assert_syscall_state(SYSCALL_SUCCESS, "inet_pton", inet_pton(AF_INET6, IPV6_SERVER, &server_addr.sin6_addr), NOT_EQUAL, -1);
	/*  We pass an invalid socket fd so the `connect` must fail. */
	int32_t mock_fd = 5;
	assert_syscall_state(SYSCALL_FAILURE, "connect", syscall(__NR_connect, mock_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)));

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
	evt_test->assert_addr_info_inet6_param(2, PPM_AF_INET6, IPV6_SERVER, IPV6_PORT_SERVER_STRING);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

TEST(SyscallEnter, connectE_UNIX)
{
	auto evt_test = new event_test(__NR_connect, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	struct sockaddr_un server_addr;
	/* BPF-side, we read the path until we face a `\0` or until we reach
	 * the maximum length (`MAX_SUN_PATH`).
	 */
	bzero(&server_addr, sizeof(server_addr));
	server_addr.sun_family = AF_UNIX;
	if(strncpy(server_addr.sun_path, UNIX_SERVER, MAX_SUN_PATH) == NULL)
	{
		FAIL() << "'strncpy' must not fail." << std::endl;
	}
	/*  We pass an invalid socket fd so the `connect` must fail. */
	int32_t mock_fd = 5;
	assert_syscall_state(SYSCALL_FAILURE, "connect", syscall(__NR_connect, mock_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)));

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
	evt_test->assert_addr_info_unix_param(2, PPM_AF_UNIX, UNIX_SERVER);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

/* This is long 109 chars, so no null terminator will be put inside the `sun_path` during the socket call.
 * The BPF prog can read at least `108` chars so instead of the `*`, it will put the `\0`.
 */
#define UNIX_LONG_PATH "/unix_socket/test/too_long/too_long/too_long/too_long/unix_socket/test/too_long/too_long/too_long/too_longgg*"
#define EXPECTED_UNIX_LONG_PATH "/unix_socket/test/too_long/too_long/too_long/too_long/unix_socket/test/too_long/too_long/too_long/too_longgg"

TEST(SyscallEnter, connectE_UNIX_max_path)
{
	auto evt_test = new event_test(__NR_connect, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	/* The unix socket pathname has the maximum length so there is
	 * no null terminator `\0`. We want to see if BPF can manage this case by putting
	 * also the terminator `\0` at the end.
	 */

	struct sockaddr_un server_addr;
	bzero(&server_addr, sizeof(server_addr));
	server_addr.sun_family = AF_UNIX;
	/* we use `memcpy` to avoid the warning message from `strncpy` */
	if(memcpy(server_addr.sun_path, UNIX_LONG_PATH, MAX_SUN_PATH) == NULL)
	{
		FAIL() << "'strncpy' must not fail." << std::endl;
	}
	/*  We pass an invalid socket fd so the `connect` must fail. */
	int32_t mock_fd = 5;
	assert_syscall_state(SYSCALL_FAILURE, "connect", syscall(__NR_connect, mock_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)));

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
	evt_test->assert_addr_info_unix_param(2, PPM_AF_UNIX, EXPECTED_UNIX_LONG_PATH);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

TEST(SyscallEnter, connectE_negative_socket)
{
	auto evt_test = new event_test(__NR_connect, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	/* We pass an invalid socket `fd` so the `connect` must fail.
	 * The invalid socket fd, in this case, is negative so the `sockaddr` param will be empty.
	 */
	int32_t mock_fd = -1;
	assert_syscall_state(SYSCALL_FAILURE, "connect", syscall(__NR_connect, mock_fd, NULL, 0));

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
	/* The param must be empty since we pass an invalid socket_id. */
	evt_test->assert_empty_param(2);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}
#endif

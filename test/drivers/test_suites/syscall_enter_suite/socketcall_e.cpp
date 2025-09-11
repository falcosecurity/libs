#include "../../event_class/event_class.h"

#ifdef __NR_socketcall

#if defined(__NR_socket) && defined(__NR_bind) && defined(__NR_connect)

#include <sys/socket.h>
#include <linux/net.h>

TEST(SyscallEnter, socketcall_connectE) {
	auto evt_test = get_syscall_event_test(__NR_connect, ENTER_EVENT);

	// TODO(ekoops): remove this test once we completely remove socketcall enter events detection in
	//  all 3 drivers.
	if(evt_test->is_modern_bpf_engine()) {
		GTEST_SKIP()
		        << "Modern eBPF probe doesn't support anymore socketcall enter events detection";
	}

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t mock_fd = -1;
	sockaddr_in server_addr;
	evt_test->server_fill_sockaddr_in(&server_addr);
	unsigned long args[3]{};
	args[0] = mock_fd;
	args[1] = (unsigned long)&server_addr;
	args[2] = sizeof(server_addr);
	assert_syscall_state(SYSCALL_FAILURE,
	                     "socketcall connect",
	                     syscall(__NR_socketcall, SYS_CONNECT, args));

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure()) {
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: fd (type: PT_FD) */
	evt_test->assert_numeric_param(1, (int64_t)mock_fd);

	/* Parameter 2: addr (type: PT_SOCKADDR) */
	evt_test->assert_addr_info_inet_param(2, PPM_AF_INET, IPV4_SERVER, IPV4_PORT_SERVER_STRING);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}
#endif

TEST(SyscallEnter, socketcall_wrong_code_socketcall_interesting) {
	// We send a wrong code so the event will be dropped
	auto evt_test = get_syscall_event_test(__NR_socketcall, ENTER_EVENT);

	// TODO(ekoops): remove this test once we completely remove socketcall enter events detection in
	//  all 3 drivers.
	if(evt_test->is_modern_bpf_engine()) {
		GTEST_SKIP()
		        << "Modern eBPF probe doesn't support anymore socketcall enter events detection";
	}

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	unsigned long args[3]{};
	args[0] = 47;
	args[1] = 0;
	args[2] = 0;
	int wrong_code = 1230;

	assert_syscall_state(SYSCALL_FAILURE, "socketcall", syscall(__NR_socketcall, wrong_code, args));

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_absence(CURRENT_PID, PPME_GENERIC_E);
}

TEST(SyscallEnter, socketcall_wrong_code_socketcall_not_interesting) {
	// Same as the previous test
	auto evt_test = get_syscall_event_test(__NR_setsockopt, ENTER_EVENT);

	// TODO(ekoops): remove this test once we completely remove socketcall enter events detection in
	//  all 3 drivers.
	if(evt_test->is_modern_bpf_engine()) {
		GTEST_SKIP()
		        << "Modern eBPF probe doesn't support anymore socketcall enter events detection";
	}

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	unsigned long args[3]{};
	args[0] = 47;
	args[1] = 0;
	args[2] = 0;
	int wrong_code = 1230;

	assert_syscall_state(SYSCALL_FAILURE, "socketcall", syscall(__NR_socketcall, wrong_code, args));

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_absence(CURRENT_PID, PPME_GENERIC_E);
}

TEST(SyscallEnter, socketcall_null_pointer_and_wrong_code_socketcall_interesting) {
	// We send a wrong code so the event will be dropped
	auto evt_test = get_syscall_event_test(__NR_socketcall, ENTER_EVENT);

	// TODO(ekoops): remove this test once we completely remove socketcall enter events detection in
	//  all 3 drivers.
	if(evt_test->is_modern_bpf_engine()) {
		GTEST_SKIP()
		        << "Modern eBPF probe doesn't support anymore socketcall enter events detection";
	}

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int wrong_code = 1230;
	assert_syscall_state(SYSCALL_FAILURE, "socketcall", syscall(__NR_socketcall, wrong_code, NULL));

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_absence(CURRENT_PID, PPME_GENERIC_E);
}

#endif /* __NR_socketcall */

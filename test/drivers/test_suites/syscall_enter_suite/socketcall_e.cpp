#include "../../event_class/event_class.h"

#ifdef __NR_socketcall

#include <sys/socket.h>
#include <linux/net.h>

TEST(SyscallEnter, socketcall_socketE)
{
	/* RIGHT NOW we enable all the syscalls, we create a dedicated helper IMHO */
	auto evt_test = get_syscall_event_test();

	evt_test->set_event_type(PPME_SOCKET_SOCKET_E);

	evt_test->enable_capture();
	/*=============================== TRIGGER SYSCALL  ===========================*/

	unsigned long args[3] = {0};
	args[0] = AF_INET;
	args[1] = SOCK_RAW;
	args[2] = PF_INET;

	syscall(__NR_socketcall, SYS_SOCKET, args);

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence(CURRENT_PID, PPME_SOCKET_SOCKET_E);

	if(HasFatalFailure())
	{
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: domain (type: PT_ENUMFLAGS32) */
	evt_test->assert_numeric_param(1, (uint32_t)args[0]);

	/* Parameter 2: type (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (uint32_t)args[1]);

	/* Parameter 3: proto (type: PT_UINT32) */
	evt_test->assert_numeric_param(3, (uint32_t)args[2]);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}

TEST(SyscallEnter, socketcall_bindE)
{
	/* RIGHT NOW we enable all the syscalls, we create a dedicated helper IMHO */
	auto evt_test = get_syscall_event_test();

	evt_test->set_event_type(PPME_SOCKET_BIND_E);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	unsigned long args[3] = {0};
	args[0] = 47;
	args[1] = 0;
	args[2] = 0;

	syscall(__NR_socketcall, SYS_BIND, args);

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence(CURRENT_PID, PPME_SOCKET_BIND_E);

	if(HasFatalFailure())
	{
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: fd (type: PT_FD) */
	evt_test->assert_numeric_param(1, (int64_t)args[0]);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}

#endif

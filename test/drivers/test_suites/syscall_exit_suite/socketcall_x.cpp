#include "../../event_class/event_class.h"

#ifdef __NR_socketcall

#include <sys/socket.h>
#include <linux/net.h>

TEST(SyscallExit, socketcall_socketX)
{
	/* RIGHT NOW we enable all the syscalls, we create a dedicated helper IMHO */
	auto evt_test = get_syscall_event_test();

	evt_test->set_event_type(PPME_SOCKET_SOCKET_X);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	unsigned long args[3] = {0};
	args[0] = AF_INET;
	args[1] = SOCK_RAW;
	args[2] = PF_INET;

	int ret = syscall(__NR_socketcall, SYS_SOCKET, &args);

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence(CURRENT_PID, PPME_SOCKET_SOCKET_X);

	if(HasFatalFailure())
	{
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO)*/
	evt_test->assert_numeric_param(1, (int64_t)ret);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif

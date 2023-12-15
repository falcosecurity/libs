#include "../../event_class/event_class.h"

#ifdef __NR_ptrace

#include <sys/ptrace.h>

TEST(SyscallEnter, ptraceE)
{
	auto evt_test = get_syscall_event_test(__NR_ptrace, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	__ptrace_request request = PTRACE_PEEKSIGINFO;
	pid_t pid = -1;
	void* addr = NULL;
	void* data = NULL;
	assert_syscall_state(SYSCALL_FAILURE, "ptrace", syscall(__NR_ptrace, request, pid, addr, data));

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

	/* Parameter 1: request (type: PT_FLAGS16) */
	evt_test->assert_numeric_param(1, (uint16_t)PPM_PTRACE_PEEKSIGINFO);

	/* Parameter 2: pid (type: PT_PID) */
	evt_test->assert_numeric_param(2, (int64_t)pid);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}
#endif

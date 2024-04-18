#include "../../event_class/event_class.h"

#ifdef __NR_ptrace

#include <sys/ptrace.h>

/// TODO: we need a test to assert the behavior in case of success.

TEST(SyscallExit, ptraceX_failure)
{
	auto evt_test = get_syscall_event_test(__NR_ptrace, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	__ptrace_request request = PTRACE_PEEKSIGINFO;
	pid_t pid = -1;
	void* addr = NULL;
	void* data = NULL;
	assert_syscall_state(SYSCALL_FAILURE, "ptrace", syscall(__NR_ptrace, request, pid, addr, data));
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

	/* Parameter 1: res (type: PT_FD) */
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/* Parameter 2: addr (type: PT_DYN) */
	evt_test->assert_ptrace_addr(2);

	/* Parameter 3: data (type: PT_DYN) */
	evt_test->assert_ptrace_addr(3);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}
#endif

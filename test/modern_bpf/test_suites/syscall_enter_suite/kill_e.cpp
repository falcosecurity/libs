#include "../../event_class/event_class.h"

#ifdef __NR_kill

TEST(SyscallEnter, killE)
{
	auto evt_test = get_syscall_event_test(__NR_kill, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	/* If `pid` is `0`, then `signal` is sent to every process in the process
	 * group of the calling process. If we use also `signal==0`, no signal is sent but
	 * we only check for the existence of a process ID or process group ID that the caller is
	 * permitted to signal. The process is always alive so the call should always succeed.
	 */
	int32_t mock_pid = 0;
	int32_t signal = 0;
	assert_syscall_state(SYSCALL_SUCCESS, "kill", syscall(__NR_kill, mock_pid, signal), NOT_EQUAL, -1);

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

	/* Parameter 1: pid (type: PT_PID) */
	evt_test->assert_numeric_param(1, (int64_t)mock_pid);

	/* Parameter 2: sig (type: PT_SIGTYPE) */
	evt_test->assert_numeric_param(2, (uint8_t)signal);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}
#endif

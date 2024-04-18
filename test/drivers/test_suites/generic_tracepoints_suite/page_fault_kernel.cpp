#include "../../event_class/event_class.h"

#if defined(CAPTURE_PAGE_FAULTS) && defined(__NR_fork) && defined(__NR_wait4)
TEST(GenericTracepoints, page_fault_kernel)
{
	auto evt_test = get_generic_event_test(PPM_SC_PAGE_FAULT_KERNEL);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	pid_t ret_pid = syscall(__NR_fork);
	if(ret_pid == 0)
	{
		exit(EXIT_SUCCESS);
	}
	assert_syscall_state(SYSCALL_SUCCESS, "fork", ret_pid, NOT_EQUAL, -1);
	int status = 0;
	int options = 0;
	assert_syscall_state(SYSCALL_SUCCESS, "wait4", syscall(__NR_wait4, ret_pid, &status, options, NULL), NOT_EQUAL, -1);

	if(__WEXITSTATUS(status) == EXIT_FAILURE || __WIFSIGNALED(status) != 0)
	{
		FAIL() << "Fork failed..." << std::endl;
	}

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence(ret_pid);

	if(HasFatalFailure())
	{
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: addr (type: PT_UINT64) */
	evt_test->assert_only_param_len(1, sizeof(uint64_t));

	/* Parameter 2: ip (type: PT_UINT64) */
	evt_test->assert_only_param_len(2, sizeof(uint64_t));

	/* Parameter 3: error (type: PT_FLAGS32) */
	evt_test->assert_only_param_len(3, sizeof(uint32_t));

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}
#endif

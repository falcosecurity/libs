#include "../../event_class/event_class.h"

#ifdef __NR_seccomp

#include <linux/seccomp.h>

TEST(SyscallEnter, seccompE)
{
	auto evt_test = get_syscall_event_test(__NR_seccomp, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	uint32_t operation = SECCOMP_SET_MODE_FILTER;
	uint32_t flags = 0;
	void* args = NULL;
	assert_syscall_state(SYSCALL_FAILURE, "seccomp", syscall(__NR_seccomp, operation, flags, args));

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

	/* Parameter 1: operation (type: PT_UINT64) */
	evt_test->assert_numeric_param(1, (uint64_t)operation);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif

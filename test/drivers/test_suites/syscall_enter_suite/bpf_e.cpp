#include "../../event_class/event_class.h"

#ifdef __NR_bpf

#include <linux/bpf.h>

TEST(SyscallEnter, bpfE)
{
	auto evt_test = get_syscall_event_test(__NR_bpf, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t cmd = -1;
	union bpf_attr *attr = NULL;
	uint32_t size = 0;
	assert_syscall_state(SYSCALL_FAILURE, "bpf", syscall(__NR_bpf, cmd, attr, size));

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

	/* Parameter 1: cmd (type: PT_INT64) */
	evt_test->assert_numeric_param(1, (int64_t)cmd);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif

#include "../../event_class/event_class.h"

#ifdef __NR_mprotect

#include <sys/mman.h>

TEST(SyscallExit, mprotectX)
{
	auto evt_test = get_syscall_event_test(__NR_mprotect, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/
	void *mock_addr = (void *)1;
	size_t mock_len = 4096;
	int mock_prot = PROT_READ | PROT_EXEC;
	assert_syscall_state(SYSCALL_FAILURE, "mprotect", syscall(__NR_mprotect, mock_addr, mock_len, mock_prot));
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

	/* Parameter 1: res (type: PT_ERRNO)*/
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif

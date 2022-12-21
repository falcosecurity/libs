#include "../../event_class/event_class.h"

#ifdef __NR_mprotect

#include <sys/mman.h>

TEST(SyscallEnter, mprotectE)
{
	auto evt_test = get_syscall_event_test(__NR_mprotect, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	void *mock_addr = (void *)0;
	size_t mock_size = 4096;
	int mock_prot = PROT_READ | PROT_EXEC;
	assert_syscall_state(SYSCALL_FAILURE, "mprotect", syscall(__NR_mprotect, mock_addr, mock_size, mock_prot));

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

	/* Parameter 1: addr (type: PT_UINT64) */
	evt_test->assert_numeric_param(1, (uint64_t)mock_addr);

	/* Parameter 2: size (type: PT_UINT64) */
	evt_test->assert_numeric_param(2, (uint64_t)mock_size);

	/* Parameter 3: prot (type: PT_FLAGS32) */
	evt_test->assert_numeric_param(3, PPM_PROT_READ | PPM_PROT_EXEC);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}
#endif

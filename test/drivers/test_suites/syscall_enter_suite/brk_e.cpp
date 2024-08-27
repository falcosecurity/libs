#include "../../event_class/event_class.h"

#ifdef __NR_brk

TEST(SyscallEnter, brkE)
{
	auto evt_test = get_syscall_event_test(__NR_brk, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	unsigned long addr = 0;
	/* brk returns the new program break on success.  On failure, the system call returns the current break,
	 * so we cannot assert its failure
	 */
	syscall(__NR_brk, addr);

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
	evt_test->assert_numeric_param(1, (uint64_t)addr);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif

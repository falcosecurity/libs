#include "../../event_class/event_class.h"

#ifdef __NR_brk

TEST(SyscallExit, brkX)
{
	auto evt_test = get_syscall_event_test(__NR_brk, EXIT_EVENT);

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

	/* Parameter 1: ret (type: PT_UINT64) */
	/* We cannot assert the value of the program break */
	evt_test->assert_only_param_len(1, sizeof(int64_t));

	/* Parameter 2: vm_size (type: PT_UINT32) */
	evt_test->assert_only_param_len(2, sizeof(uint32_t));

	/* Parameter 3: vm_rss (type: PT_UINT32) */
	evt_test->assert_only_param_len(3, sizeof(uint32_t));

	/* Parameter 4: vm_swap (type: PT_UINT32) */
	evt_test->assert_only_param_len(4, sizeof(uint32_t));

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);
}
#endif

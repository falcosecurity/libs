#include "../../event_class/event_class.h"

#ifdef __NR_mlockall

#include <sys/mman.h>

TEST(SyscallExit, mlockallX)
{
	auto evt_test = get_syscall_event_test(__NR_mlockall, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int flags = MCL_FUTURE | MCL_ONFAULT;
	assert_syscall_state(SYSCALL_SUCCESS, "mlockall", syscall(__NR_mlockall, flags), NOT_EQUAL, -1);

	/* We unlock all pages mapped into the address space of the calling process immediately to avoid
	 * issues in other tests.
	 */
	syscall(__NR_munlockall);

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
	evt_test->assert_numeric_param(1, (int64_t)0);

	/* Parameter 2: flags (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (uint32_t)PPM_MLOCKALL_MCL_FUTURE | PPM_MLOCKALL_MCL_ONFAULT);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}
#endif

#include "../../event_class/event_class.h"

#ifdef __NR_ugetrlimit

#include <sys/resource.h>

TEST(SyscallEnter, ugetrlimitE)
{
	/* Please note:
	 * the syscall `ugetrlimit` is mapped to `PPME_SYSCALL_GETRLIMIT_E` event
	 * like `getrlimit`. The same BPF program will be used for both the syscalls.
	 */

	auto evt_test = get_syscall_event_test(__NR_ugetrlimit, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int resource = RLIMIT_NPROC;
	struct rlimit *rlim = NULL;
	assert_syscall_state(SYSCALL_FAILURE, "ugetrlimit", syscall(__NR_ugetrlimit, resource, rlim));

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

	/* Parameter 1: resource (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(1, (uint8_t)PPM_RLIMIT_NPROC);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif

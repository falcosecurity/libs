#include "../../event_class/event_class.h"

#ifdef __NR_prlimit64

#include <sys/resource.h>

TEST(SyscallEnter, prlimit64E)
{
	auto evt_test = get_syscall_event_test(__NR_prlimit64, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	struct rlimit* old_rlimit = NULL;
	struct rlimit* new_rlimit = NULL;
	/* We need to put the pid to `-1` otherwise the syscall won't fail on some machines. */
	pid_t pid = -1;
	int resource = RLIMIT_NOFILE;
	assert_syscall_state(SYSCALL_FAILURE, "prlimit64", syscall(__NR_prlimit64, pid, resource, &new_rlimit, &old_rlimit));

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
	evt_test->assert_numeric_param(1, (int64_t)pid);

	/* Parameter 2: resource (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(2, (uint8_t)PPM_RLIMIT_NOFILE);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}
#endif

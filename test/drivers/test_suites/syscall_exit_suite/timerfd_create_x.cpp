#include "../../event_class/event_class.h"

#ifdef __NR_timerfd_create
TEST(SyscallExit, timerfd_createX)
{
	auto evt_test = get_syscall_event_test(__NR_timerfd_create, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	/* `clockid` and `flags` are not caught BPF side, we always send `0` */
	int clockid = -1;
	int flags = -1;
	assert_syscall_state(SYSCALL_FAILURE,"timerfd_create", syscall(__NR_timerfd_create, clockid, flags));
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

	/* Parameter 1: res (type: PT_FD) */
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif

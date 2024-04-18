#include "../../event_class/event_class.h"

#ifdef __NR_timerfd_create
TEST(SyscallEnter, timerfd_createE)
{
	auto evt_test = get_syscall_event_test(__NR_timerfd_create, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	/* `clockid` and `flags` are not caught BPF side, we always send `0` */
	int clockid = -1;
	int flags = -1;
	assert_syscall_state(SYSCALL_FAILURE,"timerfd_create", syscall(__NR_timerfd_create, clockid, flags));

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

	/* Parameter 1: clockid (type: PT_UINT8) */
	evt_test->assert_numeric_param(1, (uint8_t)0);

	/* Parameter 2: flags (type: PT_FLAGS8) */
	evt_test->assert_numeric_param(2, (uint8_t)0);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}
#endif

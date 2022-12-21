#include "../../event_class/event_class.h"

#ifdef __NR_mlock

#include <sys/mman.h>

TEST(SyscallEnter, mlockE)
{
	auto evt_test = get_syscall_event_test(__NR_mlock, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	void *mock_addr = (void *)0;
	size_t mock_len = 4096;
	assert_syscall_state(SYSCALL_FAILURE, "mlock", syscall(__NR_mlock, mock_addr, mock_len));

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

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(0);
}
#endif

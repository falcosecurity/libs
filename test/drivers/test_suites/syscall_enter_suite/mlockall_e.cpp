#include "../../event_class/event_class.h"

#ifdef __NR_mlockall

#include <sys/mman.h>

TEST(SyscallEnter, mlockallE)
{
	auto evt_test = get_syscall_event_test(__NR_mlockall, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	unsigned long mock_flags{0};
	assert_syscall_state(SYSCALL_FAILURE, "mlockall", syscall(__NR_mlockall, mock_flags));

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

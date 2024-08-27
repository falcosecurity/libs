#include "../../event_class/event_class.h"

#ifdef __NR_munmap

#include <sys/mman.h>

TEST(SyscallEnter, munmapE)
{
	auto evt_test = get_syscall_event_test(__NR_munmap, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	void *mock_addr = (void *)1;
	size_t mock_length = 1023;
	assert_syscall_state(SYSCALL_FAILURE, "munmap", syscall(__NR_munmap, mock_addr, mock_length));

	/*=============================== TRIGGER SYSCALL  ===========================*/

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

	/* Parameter 2: length (type: PT_UINT64) */
	evt_test->assert_numeric_param(2, (uint64_t)mock_length);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}
#endif

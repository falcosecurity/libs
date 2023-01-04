#include "../../event_class/event_class.h"

#ifdef __NR_munlock

#include <sys/mman.h>

TEST(SyscallExit, munlockX)
{
	auto evt_test = get_syscall_event_test(__NR_munlock, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	void *mock_addr = (void *)0;
	size_t mock_len = 37;
	assert_syscall_state(SYSCALL_FAILURE, "munlock", syscall(__NR_munlock, mock_addr, mock_len));
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

	/* Parameter 1: res (type: PT_ERRNO)*/
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/* Parameter 2: addr (type: PT_UINT64) */
	evt_test->assert_numeric_param(2, (uint64_t)mock_addr);

	/* Parameter 3: len (type: PT_UINT64) */
	evt_test->assert_numeric_param(3, (uint64_t)mock_len);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}
#endif

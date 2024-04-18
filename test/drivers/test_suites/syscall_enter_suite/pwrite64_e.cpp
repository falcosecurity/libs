#include "../../event_class/event_class.h"

#ifdef __NR_pwrite64

TEST(SyscallEnter, pwrite64E)
{
	auto evt_test = get_syscall_event_test(__NR_pwrite64, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int mock_fd = -1;
	char* mock_buf = NULL;
	size_t mock_count = 4096;
	off_t off = 16;
	assert_syscall_state(SYSCALL_FAILURE, "pwrite64", syscall(__NR_pwrite64, mock_fd, (void*)(mock_buf), mock_count, off));

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

	/* Parameter 1: fd (type: PT_FD) */
	evt_test->assert_numeric_param(1, (int64_t)mock_fd);

	/* Parameter 2: size (type: PT_UINT32)*/
	evt_test->assert_numeric_param(2, (uint32_t)mock_count);

	/* Parameter 3: pos (type: PT_UINT64) */
	evt_test->assert_numeric_param(3, (uint64_t)off);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}
#endif

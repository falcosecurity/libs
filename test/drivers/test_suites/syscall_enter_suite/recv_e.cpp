#include "../../event_class/event_class.h"

#ifdef __NR_recv

TEST(SyscallEnter, recvE) {
	auto evt_test = get_syscall_event_test(__NR_recv, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t mock_fd = -1;
	char* mock_buf = NULL;
	size_t mock_count = DEFAULT_SNAPLEN;
	int flags = 0;
	assert_syscall_state(SYSCALL_FAILURE,
	                     "recv",
	                     syscall(__NR_recv, mock_fd, (void*)(mock_buf), mock_count, flags));

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure()) {
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: fd (type: PT_FD) */
	evt_test->assert_numeric_param(1, (int64_t)mock_fd);

	/* Parameter 2: size (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (uint32_t)mock_count);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}
#endif

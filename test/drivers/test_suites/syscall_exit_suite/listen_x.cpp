#include "../../event_class/event_class.h"

#ifdef __NR_listen
TEST(SyscallExit, listenX) {
	auto evt_test = get_syscall_event_test(__NR_listen, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t socket_fd = 2;
	int backlog = 3;
	assert_syscall_state(SYSCALL_FAILURE, "listen", syscall(__NR_listen, socket_fd, backlog));
	int64_t errno_value = -errno;

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure()) {
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/* Parameter 2: fd (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)socket_fd);

	/* Parameter 3: backlog (type: PT_INT32) */
	evt_test->assert_numeric_param(3, (int32_t)backlog);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}
#endif

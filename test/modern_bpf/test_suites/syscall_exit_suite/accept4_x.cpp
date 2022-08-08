#include "../../event_class/event_class.h"

#ifdef __NR_accept4

/* We follow the same BPF logic of the `accept` so right now there is no need to test all
 * cases like in the `accept` syscall, here we only want to test that the correct BPF program
 * is called.
 */

TEST(SyscallExit, accept4X_failure)
{
	auto evt_test = new event_test(__NR_accept4, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t mock_fd = -1;
	struct sockaddr *addr = NULL;
	socklen_t *addrlen = NULL;
	int flags = 0;
	assert_syscall_state(SYSCALL_FAILURE, "accept4", syscall(__NR_accept4, mock_fd, addr, addrlen, flags));
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

	/* Parameter 1: fd (type: PT_FD) */
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/* Parameter 2: tuple (type: PT_SOCKTUPLE) */
	evt_test->assert_empty_param(2);

	/* Parameter 3: queuepct (type: PT_UINT8) */
	evt_test->assert_numeric_param(3, (uint8_t)0);

	/* Parameter 4: queuelen (type: PT_UINT32) */
	evt_test->assert_numeric_param(4, (uint32_t)0);

	/* Parameter 5: queuemax (type: PT_UINT32) */
	evt_test->assert_numeric_param(5, (uint32_t)0);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}
#endif

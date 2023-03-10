#include "../../event_class/event_class.h"

#ifdef __NR_send
TEST(SyscallExit, sendX_fail)
{
	auto evt_test = get_syscall_event_test(__NR_send, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t mock_fd = -1;
	const unsigned data_len = DEFAULT_SNAPLEN * 2;
	char buf[data_len] = "some-data";
	int flags = 0 assert_syscall_state(SYSCALL_FAILURE, "send", syscall(__NR_send, mock_fd, (void *)buf, data_len, flags));
	int errno_value = -errno;

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

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/* Parameter 2: data (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(2, buf, DEFAULT_SNAPLEN);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}
#endif

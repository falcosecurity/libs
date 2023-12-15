#include "../../event_class/event_class.h"

#ifdef __NR_recvfrom

TEST(SyscallEnter, recvfromE)
{
	auto evt_test = get_syscall_event_test(__NR_recvfrom, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t mock_fd = -1;
	char received_data[MAX_RECV_BUF_SIZE];
	socklen_t received_data_len = MAX_RECV_BUF_SIZE;
	uint32_t flags = 0;
	sockaddr* src_addr = NULL;
	socklen_t *addrlen = NULL;
	assert_syscall_state(SYSCALL_FAILURE, "recvfrom", syscall(__NR_recvfrom, mock_fd, received_data, received_data_len, flags, src_addr, addrlen));

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
	evt_test->assert_numeric_param(2, (uint32_t)received_data_len);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}
#endif

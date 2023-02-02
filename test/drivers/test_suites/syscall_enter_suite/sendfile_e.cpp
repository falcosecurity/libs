#include "../../event_class/event_class.h"

#ifdef __NR_sendfile

TEST(SyscallEnter, sendfileE_null_pointer)
{
	auto evt_test = get_syscall_event_test(__NR_sendfile, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int out_fd = -1;
	int in_fd = -2;
	void* offsite = NULL;
	unsigned long size = 37;
	assert_syscall_state(SYSCALL_FAILURE, "sendfile", syscall(__NR_sendfile, out_fd, in_fd, offsite, size));

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

	/* Parameter 1: out_fd (type: PT_FD) */
	evt_test->assert_numeric_param(1, (int64_t)out_fd);

	/* Parameter 2: in_fd (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)in_fd);

	/* Parameter 3: offset (type: PT_UINT64) */
	/* The pointer is NULL so the offset should be 0 */
	evt_test->assert_numeric_param(3, (uint64_t)0);

	/* Parameter 4: size (type: PT_UINT64) */
	evt_test->assert_numeric_param(4, (uint64_t)size);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);
}

TEST(SyscallEnter, sendfileE)
{
	auto evt_test = get_syscall_event_test(__NR_sendfile, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int out_fd = -1;
	int in_fd = -2;
	unsigned long offsite = 24;
	unsigned long size = 37;
	assert_syscall_state(SYSCALL_FAILURE, "sendfile", syscall(__NR_sendfile, out_fd, in_fd, &offsite, size));

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

	/* Parameter 1: out_fd (type: PT_FD) */
	evt_test->assert_numeric_param(1, (int64_t)out_fd);

	/* Parameter 2: in_fd (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)in_fd);

	/* Parameter 3: offset (type: PT_UINT64) */
	evt_test->assert_numeric_param(3, (uint64_t)offsite);

	/* Parameter 4: size (type: PT_UINT64) */
	evt_test->assert_numeric_param(4, (uint64_t)size);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);
}
#endif

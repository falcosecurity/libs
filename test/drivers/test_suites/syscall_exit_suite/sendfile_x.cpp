#include "../../event_class/event_class.h"

#ifdef __NR_sendfile

TEST(SyscallExit, sendfileX_null_pointer)
{
	auto evt_test = get_syscall_event_test(__NR_sendfile, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int out_fd = -1;
	int in_fd = -2;
	void* offsite = NULL;
	unsigned long size = 37;
	assert_syscall_state(SYSCALL_FAILURE, "sendfile", syscall(__NR_sendfile, out_fd, in_fd, offsite, size));
	int64_t errno_value = -errno;

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

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/* Parameter 2: offset (type: PT_UINT64) */
	/* The pointer is NULL so the offset should be 0 */
	evt_test->assert_numeric_param(2, (uint64_t)0);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

TEST(SyscallExit, sendfileX)
{
	auto evt_test = get_syscall_event_test(__NR_sendfile, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int out_fd = -1;
	int in_fd = -2;
	unsigned long offsite = 24;
	unsigned long size = 37;
	assert_syscall_state(SYSCALL_FAILURE, "sendfile", syscall(__NR_sendfile, out_fd, in_fd, &offsite, size));
	int64_t errno_value = -errno;

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

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/* Parameter 2: offset (type: PT_UINT64) */
	/* The syscall fails so the offsite is not overwritten by the kernel */
	evt_test->assert_numeric_param(2, (uint64_t)offsite);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}
#endif

#include "../../event_class/event_class.h"

#ifdef __NR_fchown
TEST(SyscallExit, fchownX)
{
	auto evt_test = get_syscall_event_test(__NR_fchown, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t mock_fd = -1;
	uint32_t uid = 0;
	uint32_t gid = 0;
	assert_syscall_state(SYSCALL_FAILURE, "fchown", syscall(__NR_fchown, mock_fd, uid, gid));
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

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/* Parameter 2: fd (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)mock_fd);

	/* Parameter 3: uid (type: PT_UINT32) */
	evt_test->assert_numeric_param(3, (uint32_t)uid);

	/* Parameter 4: gid (type: PT_UINT32) */
	evt_test->assert_numeric_param(4, (uint32_t)gid);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);
}
#endif

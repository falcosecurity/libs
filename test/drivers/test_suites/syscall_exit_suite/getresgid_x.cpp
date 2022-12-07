#include "../../event_class/event_class.h"

#ifdef __NR_getresgid
TEST(SyscallExit, getresgidX)
{
	auto evt_test = get_syscall_event_test(__NR_getresgid, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	gid_t rgid{0};
	gid_t egid{0};
	gid_t sgid{0};
	assert_syscall_state(SYSCALL_SUCCESS, "getresgid", syscall(__NR_getresgid, &rgid, &egid, &sgid), NOT_EQUAL, -1);
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
	evt_test->assert_numeric_param(1, errno_value);

	/* Parameter 2: ruid (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, rgid);

	/* Parameter 3: euid (type: PT_UINT32) */
	evt_test->assert_numeric_param(3, egid);

	/* Parameter 4: suid (type: PT_UINT32) */
	evt_test->assert_numeric_param(4, sgid);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);
}
#endif

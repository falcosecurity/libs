#include "../../event_class/event_class.h"

#ifdef __NR_getresgid
TEST(SyscallExit, getresgidX)
{
	auto evt_test = get_syscall_event_test(__NR_getresgid, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	gid_t rgid;
	gid_t egid;
	gid_t sgid;

	int res = syscall(__NR_getresgid, &rgid, &egid, &sgid);
	assert_syscall_state(SYSCALL_SUCCESS, "getresgid", res, NOT_EQUAL, -1);

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
        evt_test->assert_numeric_param(1, (int64_t)res);

	/* Parameter 2: ruid (type: PT_GID) */
	evt_test->assert_numeric_param(2, (uint32_t)rgid);

	/* Parameter 3: euid (type: PT_GID) */
	evt_test->assert_numeric_param(3, (uint32_t)egid);

	/* Parameter 4: suid (type: PT_GID) */
	evt_test->assert_numeric_param(4, (uint32_t)sgid);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);
}
#endif

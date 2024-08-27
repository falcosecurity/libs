#include "../../event_class/event_class.h"

#ifdef __NR_getresuid
TEST(SyscallExit, getresuidX)
{
	auto evt_test = get_syscall_event_test(__NR_getresuid, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	uid_t ruid;
	uid_t euid;
	uid_t suid;

	int res = syscall(__NR_getresuid, &ruid, &euid, &suid);
	assert_syscall_state(SYSCALL_SUCCESS, "getresuid", res, NOT_EQUAL, -1);

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

	/* Parameter 2: ruid (type: PT_UID) */
	evt_test->assert_numeric_param(2, (uint32_t)ruid);

	/* Parameter 3: euid (type: PT_UID) */
	evt_test->assert_numeric_param(3, (uint32_t)euid);

	/* Parameter 4: suid (type: PT_UID) */
	evt_test->assert_numeric_param(4, (uint32_t)suid);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);
}
#endif

#include "../../event_class/event_class.h"

#ifdef __NR_umount2

#include <sys/mount.h>

TEST(SyscallEnter, umount2E)
{
	auto evt_test = get_syscall_event_test(__NR_umount2, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	const char* target = "/no_mount_point/xyzk-target";
	unsigned long flags = MNT_FORCE;
	assert_syscall_state(SYSCALL_FAILURE, "umount2", syscall(__NR_umount2, target, flags));

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

	/* Parameter 1: flags (type: PT_FLAGS32) */
	evt_test->assert_numeric_param(1, (uint32_t)MNT_FORCE);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif

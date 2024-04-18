#include "../../event_class/event_class.h"

#ifdef __NR_mount

#include <sys/mount.h>

TEST(SyscallEnter, mountE)
{
	auto evt_test = get_syscall_event_test(__NR_mount, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	const char* source = "/no_mount_point/xyzk-source";
	const char* target = "/no_mount_point/xyzk-target";
	const char* filesystemtype = "not_supported";
	unsigned long flags = MS_MGC_VAL | MS_RDONLY;
	const void* data = NULL;
	assert_syscall_state(SYSCALL_FAILURE, "mount", syscall(__NR_mount, source, target, filesystemtype, flags, data));

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
	/* According to the driver logic `MS_MGC_VAL` should be removed so here
	 * we will obtain only `MS_RDONLY`
	 */
	evt_test->assert_numeric_param(1, (uint32_t)MS_RDONLY);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif

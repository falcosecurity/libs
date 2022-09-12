#include "../../event_class/event_class.h"

#ifdef __NR_mount

#include <sys/mount.h>

TEST(SyscallExit, mountX)
{
	auto evt_test = get_syscall_event_test(__NR_mount, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	const char* source = "/no_mount_point/xyzk-source";
	const char* target = "/no_mount_point/xyzk-target";
	const char* filesystemtype = "not_supported";
	unsigned long flags = MS_MGC_VAL | MS_RDONLY;
	const void* data = NULL;
	assert_syscall_state(SYSCALL_FAILURE, "mount", syscall(__NR_mount, source, target, filesystemtype, flags, data));
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

	/* Parameter 2: dev (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(2, source);

	/* Parameter 3: dir (type: PT_FSPATH) */
	evt_test->assert_charbuf_param(3, target);

	/* Parameter 4: type (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(4, filesystemtype);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);
}
#endif

#include "../../event_class/event_class.h"

#if defined(__NR_fsconfig)

#include <linux/mount.h>

TEST(SyscallExit, fsconfigX)
{

	auto evt_test = get_syscall_event_test(__NR_fsconfig, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

    int fd = 0;
    uint32_t cmd = FSCONFIG_SET_FLAG;
    const char* key = NULL;
    /* This is the case in which we pass a not-NUL value with a wrong length. */
    const char* value = "test-value";
    int aux = 20;
	int32_t ret = syscall(__NR_fsconfig, fd, cmd, key, value, aux);
	assert_syscall_state(SYSCALL_FAILURE, "fsconfig", ret);
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

	evt_test->assert_numeric_param(1, (int64_t)errno_value);
	evt_test->assert_numeric_param(2, (int64_t)fd);
	evt_test->assert_numeric_param(3, PPM_FSCONFIG_SET_FLAG);
	evt_test->assert_empty_param(4);
	evt_test->assert_empty_param(5);
	evt_test->assert_empty_param(6);
	evt_test->assert_numeric_param(7, aux);


	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(7);
}
#endif

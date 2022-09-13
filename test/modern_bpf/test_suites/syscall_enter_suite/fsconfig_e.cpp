#include "../../event_class/event_class.h"

#if defined(__NR_fsconfig)
TEST(SyscallEnter, fsconfigE)
{

	auto evt_test = get_syscall_event_test(__NR_fsconfig, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

    int fd = 0;
    uint32_t cmd = 0;
    const char* key = NULL;
    const char* value = NULL;
    int aux = 0;
	int32_t ret = syscall(__NR_fsconfig, fd, cmd, key, value, aux);
	assert_syscall_state(SYSCALL_FAILURE, "fsconfig", ret);
	syscall(__NR_close, fd);

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

	// Here we have no parameters to assert.

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(0);
}
#endif

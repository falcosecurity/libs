#include "../../event_class/event_class.h"
#if defined(__NR_mknod)
#include <sys/sysmacros.h>
TEST(SyscallEnter, mknodE_failure)
{
	auto evt_test = get_syscall_event_test(__NR_mknod, ENTER_EVENT);
	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	char path[] = "/tmp/";

	uint32_t mode = 0060000 | 0666;
	uint32_t dev = 61440;
	assert_syscall_state(SYSCALL_FAILURE, "mknod", syscall(__NR_mknod, (void *)(path), (mode_t)mode, (dev_t)dev));
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

	// Here we have no parameters to assert.

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(0);

}
#endif

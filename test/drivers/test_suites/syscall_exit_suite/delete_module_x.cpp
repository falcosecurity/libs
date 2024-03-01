#include "../../event_class/event_class.h"

#if defined(__NR_delete_module)
#include <linux/module.h>

TEST(SyscallExit, delete_moduleX_failure)
{
	const char* module_name = "test_module";

	auto evt_test = get_syscall_event_test(__NR_delete_module, EXIT_EVENT);
	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/*
	 * Call the `delete_module` syscall
	 */
	assert_syscall_state(SYSCALL_FAILURE, "delete_module", syscall(__NR_delete_module, module_name, O_TRUNC | O_NONBLOCK));
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

	/* Parameter 1: res (type: PT_ERRNO)*/
	evt_test->assert_numeric_param(1, (uint64_t)errno_value);

	/* Parameter 2: name (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(2, module_name);

	/* Parameter 3: flags (type: PT_INT32) */
	evt_test->assert_numeric_param(3, PPM_DELETE_MODULE_O_TRUNC | PPM_DELETE_MODULE_O_NONBLOCK);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}

#endif /* __NR_delete_module */
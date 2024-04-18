#include "../../event_class/event_class.h"

#ifdef __NR_capset

#include <sys/capability.h>

TEST(SyscallEnter, capsetE)
{
	auto evt_test = get_syscall_event_test(__NR_capset, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	/* - `cap_user_header_t` is a pointer to `__user_cap_header_struct`
	 * - `cap_user_data_t` is a pointer to `__user_cap_data_struct`
	 */
	cap_user_header_t hdrp = NULL;
	cap_user_data_t datap = NULL;
	assert_syscall_state(SYSCALL_FAILURE, "capset", syscall(__NR_capset, hdrp, datap));

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

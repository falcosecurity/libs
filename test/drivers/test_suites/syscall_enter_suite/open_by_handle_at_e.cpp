#include "../../event_class/event_class.h"

#ifdef __NR_open_by_handle_at
TEST(SyscallEnter, open_by_handle_atE)
{
	auto evt_test = get_syscall_event_test(__NR_open_by_handle_at, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Syscall special notes:
	 * Here `mount_fd` is invalid so the call will fail.
	 */

	int mount_fd = -1;
	struct file_handle *fhp = NULL;
	int flags = O_RDWR;
	assert_syscall_state(SYSCALL_FAILURE, "open_by_handle_at", syscall(__NR_open_by_handle_at, mount_fd, fhp, flags));

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure())
	{
		/* This could happen if:
		 * - the syscall result state is different from the expected one.
		 * - we are not able to find the event in the ring buffers.
		 */
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

#include "../../event_class/event_class.h"

#if defined(__NR_inotify_init1)
TEST(SyscallEnter, inotify_init1E)
{

	/* Please note:
	 * the syscall `inotify_init1` is mapped to `PPME_SYSCALL_INOTIFY_INIT_E` event
	 * like `inotify_init`. The same BPF program will be used for both the syscalls.
	 */

	auto evt_test = new event_test(__NR_inotify_init1, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	/* `flags = 15` is an invalid value so the syscall will return `EINVAL` as errno. */
	uint32_t flags = 15;
	assert_syscall_state(SYSCALL_FAILURE, "inotify_init1", syscall(__NR_inotify_init1, flags));

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

	/* Parameter 1: flags (type: PT_FLAGS8) */
	/// TODO: Right now we send `0` to avoid problems with `inotify_init` since they
	/// share the same event. We need to split them.
	evt_test->assert_numeric_param(1, (uint8_t)0);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif

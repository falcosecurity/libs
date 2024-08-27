#include "../../event_class/event_class.h"

#if defined(__NR_unshare)
TEST(Actions, drop_failed_enter)
{
	auto evt_test = get_syscall_event_test(__NR_unshare, ENTER_EVENT);

	/* Enable drop failed feature */
	evt_test->enable_drop_failed();

	evt_test->enable_capture();

	/* Call the syscall with a wrong flag, so that EINVAL error is triggered */
	syscall(__NR_unshare, 12);

	/* It is an enter event, therefore it is not cut by drop failed feat */
	evt_test->assert_event_presence();

	evt_test->disable_drop_failed();

	evt_test->disable_capture();
}

TEST(Actions, drop_failed_exit)
{
	auto evt_test = get_syscall_event_test(__NR_unshare, EXIT_EVENT);

	/* Enable drop failed feature */
	evt_test->enable_drop_failed();

	evt_test->enable_capture();

	/* Call the syscall with a wrong flag, so that EINVAL error is triggered */
	syscall(__NR_unshare, 12);

	/* It is an exit event, therefore it is cut by drop failed feat */
	evt_test->assert_event_absence();

	evt_test->disable_drop_failed();

	evt_test->disable_capture();
}

TEST(Actions, drop_failed_successful)
{
	auto evt_test = get_syscall_event_test(__NR_unshare, EXIT_EVENT);

	/* Enable drop failed feature */
	evt_test->enable_drop_failed();

	evt_test->enable_capture();

	/* Call the syscall */
	syscall(__NR_unshare, 0);

	evt_test->assert_event_presence();

	evt_test->disable_drop_failed();

	evt_test->disable_capture();
}
#endif
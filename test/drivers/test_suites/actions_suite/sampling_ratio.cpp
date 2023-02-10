#include "../../event_class/event_class.h"

#if defined(__NR_unshare)
TEST(Actions, sampling_ratio_UF_ALWAYS_DROP)
{
	/* Here we set just one `UF_ALWAYS_DROP` syscall as interesting... this process will send
	 * only this specific syscall and we have to check that the corresponding event is dropped when
	 * the sampling logic is enabled and not dropped when the logic is disabled.
	 */
	auto evt_test = get_syscall_event_test(__NR_unshare, ENTER_EVENT);

	/* We are not sampling, we are just removing the `UF_ALWAYS_DROP` events */
	evt_test->enable_sampling_logic(1);

	evt_test->enable_capture();

	/* Call the `UF_ALWAYS_DROP` syscall */
	syscall(__NR_unshare, 0);

	evt_test->assert_event_absence();

	evt_test->disable_sampling_logic();

	/* Call again the `UF_ALWAYS_DROP` syscall */
	syscall(__NR_unshare, 0);

	/* This time we should be able to find the event */
	evt_test->assert_event_presence();

	evt_test->disable_capture();
}
#endif

#if defined(__NR_eventfd) && defined(__NR_close)
TEST(Actions, sampling_ratio_UF_NEVER_DROP)
{
	/* Here we set just one `UF_NEVER_DROP` syscall as interesting... this process will send
	 * only this specific syscall and we have to check that the corresponding event is
     * not dropped when the sampling logic is enabled.
	 */
	auto evt_test = get_syscall_event_test(__NR_eventfd, ENTER_EVENT);

	evt_test->enable_capture();

	/* Even sampling with the maximum frequency we shouldn't drop `UF_NEVER_DROP` events */
	evt_test->enable_sampling_logic(128);

	/* Call the `UF_NEVER_DROP` syscall */
	int32_t fd = syscall(__NR_eventfd, 3);
	syscall(__NR_close, fd);

    /* We should find the event */
	evt_test->assert_event_presence();

	evt_test->disable_sampling_logic();

	evt_test->disable_capture();
}
#endif

#if defined(__NR_capset)
TEST(Actions, sampling_ratio_NO_FLAGS)
{
	/* Here we set just one syscall with no flags (UF_ALWAYS_DROP/UF_NEVER_DROP)
     * as interesting... this process will send only this specific syscall and 
     * we have to check that the corresponding event is not dropped when the
     * sampling logic is enabled with ratio==1.
	 */
	auto evt_test = get_syscall_event_test(__NR_capset, ENTER_EVENT);

	evt_test->enable_capture();

	/* With sampling==1 we shouldn't drop events without flags */
	evt_test->enable_sampling_logic(1);

	/* Call the syscall */
	syscall(__NR_capset, NULL, NULL);

    /* We should find the event */
	evt_test->assert_event_presence();

	evt_test->disable_sampling_logic();

	evt_test->disable_capture();
}
#endif

#include <gtest/gtest.h>
#include <libsinsp/sinsp.h>

/* Check the `is_unused_event` API works correctly */
TEST(events, check_unused_events) {
	ASSERT_EQ(libsinsp::events::is_unused_event(PPME_SYSCALL_EXECVE_8_E), false);
	ASSERT_EQ(libsinsp::events::is_unused_event(PPME_SCHEDSWITCH_6_X), true);
	ASSERT_EQ(libsinsp::events::is_unused_event(PPME_SYSCALL_QUOTACTL_X), false);
}

/* Check the `is_old_version_event` API works correctly */
TEST(events, check_old_version_events) {
	ASSERT_EQ(libsinsp::events::is_old_version_event(PPME_SYSCALL_EXECVE_8_E), true);
	ASSERT_EQ(libsinsp::events::is_old_version_event(PPME_SCHEDSWITCH_6_X), false);
}

/* Check if the events category is correct */
TEST(events, check_events_category) {
	/* Assert that the API works good */
	ASSERT_EQ(libsinsp::events::is_syscall_event(PPME_SYSCALL_EXECVE_8_E), true);
	ASSERT_EQ(libsinsp::events::is_syscall_event(PPME_SCHEDSWITCH_6_X), false);

	ASSERT_EQ(libsinsp::events::is_tracepoint_event(PPME_SCHEDSWITCH_6_E), true);
	ASSERT_EQ(libsinsp::events::is_tracepoint_event(PPME_SYSCALL_CLONE_20_X), false);

	ASSERT_EQ(libsinsp::events::is_metaevent(PPME_DROP_E), true);
	ASSERT_EQ(libsinsp::events::is_metaevent(PPME_SYSCALL_CLONE_20_X), false);

	ASSERT_EQ(libsinsp::events::is_unknown_event(PPME_SCHEDSWITCH_1_X), true);
	ASSERT_EQ(libsinsp::events::is_unknown_event(PPME_SYSCALL_CLONE_20_X), false);

	ASSERT_EQ(libsinsp::events::is_plugin_event(PPME_PLUGINEVENT_E), true);
	ASSERT_EQ(libsinsp::events::is_plugin_event(PPME_SYSCALL_CLONE_20_X), false);
}

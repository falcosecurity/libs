#include <gtest/gtest.h>
#include <sinsp.h>

/* Check the `is_unused_event` API works correctly */
TEST(Events, check_unused_events)
{
	/* `PPME_SYSCALL_EXECVE_8_E` has the `EF_OLD_VERSION` flag */
    ASSERT_EQ(sinsp::is_unused_event(PPME_SYSCALL_EXECVE_8_E), false);

	/* `PPME_SCHEDSWITCH_6_X` has the `EF_UNUSED` flag */
	ASSERT_EQ(sinsp::is_unused_event(PPME_SCHEDSWITCH_6_X), true);

	/* `PPME_DROP_E` has the `EF_SKIPPARSERESET` flag */
	ASSERT_EQ(sinsp::is_unused_event(PPME_DROP_E), true);

	/* `PPME_SYSCALL_QUOTACTL_E` has no flags in this set */
	ASSERT_EQ(sinsp::is_unused_event(PPME_SYSCALL_QUOTACTL_E), false);
}


/* Check the `is_old_version_event` API works correctly */
TEST(Events, check_old_version_events)
{
	/* `PPME_SYSCALL_EXECVE_8_E` has only the `EF_OLD_VERSION` flag */
    ASSERT_EQ(sinsp::is_old_version_event(PPME_SYSCALL_EXECVE_14_E), true);

	/* `PPME_SCHEDSWITCH_6_X` has no the `EF_OLD_VERSION` flag */
	ASSERT_EQ(sinsp::is_old_version_event(PPME_SCHEDSWITCH_6_X), false);
}

#include <gtest/gtest.h>
#include <sinsp.h>

/* These numbers must be updated when we add new events */
#define SYSCALL_EVENTS_NUM 326
#define TRACEPOINT_EVENTS_NUM 7
#define INTERNAL_EVENTS_NUM 20
#define UNKNOWN_EVENTS_NUM 19

/* Check if the events category is correct in our event table.
 * This test will not pass if we forget to update the event table
 * with one of these event categories!
 */
TEST(EventTable, check_events_category)
{
	int num_syscall_events = 0;
	int num_tracepoint_events = 0;
	int num_internal_events = 0;
	int num_unknown_events = 0;

	for(int event_num = 0; event_num < PPM_EVENT_MAX; event_num++)
	{
		if(g_infotables.m_event_info[event_num].category & EC_SYSCALL)
		{
			num_syscall_events++;
		}

		if(g_infotables.m_event_info[event_num].category & EC_TRACEPOINT)
		{
			num_tracepoint_events++;
		}

		if(g_infotables.m_event_info[event_num].category & EC_INTERNAL)
		{
			num_internal_events++;
		}

		/* Please note this is not an `&` but an `==` if one event has
		 * the `EC_UNKNOWN` category, it must have only this category!
		 */
		if(g_infotables.m_event_info[event_num].category == EC_UNKNOWN)
		{
			num_unknown_events++;
		}
	}

	ASSERT_EQ(num_syscall_events, SYSCALL_EVENTS_NUM);
	ASSERT_EQ(num_tracepoint_events, TRACEPOINT_EVENTS_NUM);
	ASSERT_EQ(num_internal_events, INTERNAL_EVENTS_NUM);
	ASSERT_EQ(num_unknown_events, UNKNOWN_EVENTS_NUM);
}

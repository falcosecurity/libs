#include <gtest/gtest.h>
#include <sinsp.h>

/* These numbers must be updated when we add new events */
#define SYSCALL_EVENTS_NUM 328
#define TRACEPOINT_EVENTS_NUM 7
#define METAEVENTS_NUM 19
#define PLUGIN_EVENTS_NUM 1
#define UNKNOWN_EVENTS_NUM 19

/* Check if the events category is correct in our event table.
 * This test will not pass if we forget to update the event table
 * with one of these event categories!
 */
TEST(event_table, check_events_category)
{
	int num_syscall_events = 0;
	int num_tracepoint_events = 0;
	int num_metaevents = 0;
	int num_plugin_events = 0;
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

		if(g_infotables.m_event_info[event_num].category & EC_METAEVENT)
		{
			num_metaevents++;
		}

		if(g_infotables.m_event_info[event_num].category & EC_PLUGIN)
		{
			num_plugin_events++;
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
	ASSERT_EQ(num_metaevents, METAEVENTS_NUM);
	ASSERT_EQ(num_plugin_events, PLUGIN_EVENTS_NUM);
	ASSERT_EQ(num_unknown_events, UNKNOWN_EVENTS_NUM);
	ASSERT_EQ(num_syscall_events + num_tracepoint_events + num_metaevents + num_plugin_events + num_unknown_events, PPM_EVENT_MAX);
}

/* The event category is composed of 2 parts:
 * 1. The highest bits represent the event category:
 *   - `EC_SYSCALL`
 *   - `EC_TRACEPOINT
 *   - `EC_PLUGIN`
 *   - `EC_METAEVENT`
 *
 * 2. The lowest bits represent the syscall category
 * to which the specific event belongs.
 *
 * Here we want to check that all events have a unique syscall category since
 * the lowest bits are used as an enum!
 */
TEST(event_table, check_unique_events_syscall_category)
{
	const int bitmask = EC_SYSCALL - 1;
	int event_num = 0;
	for(event_num = 0; event_num < PPM_EVENT_MAX; event_num++)
	{

		switch(g_infotables.m_event_info[event_num].category & bitmask)
		{
		case EC_UNKNOWN:
		case EC_OTHER:
		case EC_FILE:
		case EC_NET:
		case EC_IPC:
		case EC_MEMORY:
		case EC_PROCESS:
		case EC_SLEEP:
		case EC_SYSTEM:
		case EC_SIGNAL:
		case EC_USER:
		case EC_TIME:
		case EC_PROCESSING:
		case EC_IO_READ:
		case EC_IO_WRITE:
		case EC_IO_OTHER:
		case EC_WAIT:
		case EC_SCHEDULER:
		case EC_INTERNAL:
			break;
		
		/* If we fall here it means that some events have more than one syscall category! */
		default:
			goto end;
			break;
		}	
	}

end:
	ASSERT_EQ(event_num, PPM_EVENT_MAX);
}

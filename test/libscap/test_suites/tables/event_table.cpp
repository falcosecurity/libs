#include "scap.h"
#include <gtest/gtest.h>
#include <event_stats.h>

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
		if(scap_get_event_category_from_event((ppm_event_code)event_num) == EC_SYSCALL)
		{
			num_syscall_events++;
		}

		if(scap_get_event_category_from_event((ppm_event_code)event_num) == EC_TRACEPOINT)
		{
			num_tracepoint_events++;
		}

		if(scap_get_event_category_from_event((ppm_event_code)event_num) == EC_METAEVENT)
		{
			num_metaevents++;
		}

		if(scap_get_event_category_from_event((ppm_event_code)event_num) == EC_PLUGIN)
		{
			num_plugin_events++;
		}

		/* Please note this is not an `&` but an `==` if one event has
		 * the `EC_UNKNOWN` category, it must have only this category!
		 */
		if(scap_get_syscall_category_from_event((ppm_event_code)event_num) == EC_UNKNOWN)
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
    int event_num = 0;
	for(event_num = 0; event_num < PPM_EVENT_MAX; event_num++)
	{
		switch(scap_get_syscall_category_from_event((ppm_event_code)event_num))
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

TEST(event_table, check_event_names)
{
	std::map<std::string, int> event_names_count;

	for(int evt = 0; evt < PPM_EVENT_MAX; evt++)
	{
		struct ppm_event_info info = scap_get_event_info_table()[evt];

		if(info.flags & EF_OLD_VERSION)
		{
			continue;
		}

		event_names_count[info.name]++;
	}

	for(const auto& evt : event_names_count)
	{
		/* NA occurrences should be equal to unknown events number, so more than 2 */
		if(evt.first.compare("NA") != 0)
		{
			/* all events that use exit and enter events should have `evt.second == 2`
			 * while events paired with a `NA` event should have `evt.second == 1`
			 */
			ASSERT_TRUE(evt.second <= 2) << "[fail] " << evt.first << " = " << evt.second << std::endl;
		}
	}
}

TEST(event_table, check_usage_of_EC_UNKNOWN_flag)
{
	/* Every time an event is marked with the `EC_UNKNOWN` flag we should use `NA` as its name */
	std::string unknown_name = "NA";
	for(int evt = 0; evt < PPM_EVENT_MAX; evt++)
	{
		if(unknown_name.compare(scap_get_event_info_table()[evt].name) == 0)
		{
			ASSERT_TRUE(scap_get_syscall_category_from_event((ppm_event_code)evt) == EC_UNKNOWN) << "[fail] event " << evt << " should have the EC_UNKNOWN flag";
		}

		if(scap_get_syscall_category_from_event((ppm_event_code)evt) == EC_UNKNOWN)
		{
			ASSERT_TRUE(unknown_name.compare(scap_get_event_info_table()[evt].name) == 0) << "[fail] event " << evt << " should have NA as its name";
		}
	}
}

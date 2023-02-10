#include <sinsp_events.h>

bool libsinsp::events::is_unused_event(ppm_event_code event_type)
{
	ASSERT(event_type < PPM_EVENT_MAX);
	enum ppm_event_flags flags = g_infotables.m_event_info[event_type].flags;
	return (flags & EF_UNUSED);
}

bool libsinsp::events::is_skip_parse_reset_event(ppm_event_code event_type)
{
	ASSERT(event_type < PPM_EVENT_MAX);
	enum ppm_event_flags flags = g_infotables.m_event_info[event_type].flags;
	return (flags & EF_SKIPPARSERESET);
}

bool libsinsp::events::is_old_version_event(ppm_event_code event_type)
{
	ASSERT(event_type < PPM_EVENT_MAX);
	enum ppm_event_flags flags = g_infotables.m_event_info[event_type].flags;
	return (flags & EF_OLD_VERSION);
}

bool libsinsp::events::is_syscall_event(ppm_event_code event_type)
{
	ASSERT(event_type < PPM_EVENT_MAX);
	enum ppm_event_category category = g_infotables.m_event_info[event_type].category;
	return (category & EC_SYSCALL);
}

bool libsinsp::events::is_tracepoint_event(ppm_event_code event_type)
{
	ASSERT(event_type < PPM_EVENT_MAX);
	enum ppm_event_category category = g_infotables.m_event_info[event_type].category;
	return (category & EC_TRACEPOINT);
}

bool libsinsp::events::is_metaevent(ppm_event_code event_type)
{
	ASSERT(event_type < PPM_EVENT_MAX);
	enum ppm_event_category category = g_infotables.m_event_info[event_type].category;
	return (category & EC_METAEVENT);
}

bool libsinsp::events::is_unknown_event(ppm_event_code event_type)
{
	ASSERT(event_type < PPM_EVENT_MAX);
	enum ppm_event_category category = g_infotables.m_event_info[event_type].category;
	/* Please note this is not an `&` but an `==` if one event has
	 * the `EC_UNKNOWN` category, it must have only this category!
	 */
	return (category == EC_UNKNOWN);
}

bool libsinsp::events::is_plugin_event(ppm_event_code event_type)
{
	ASSERT(event_type < PPM_EVENT_MAX);
	enum ppm_event_category category = g_infotables.m_event_info[event_type].category;
	return (category & EC_PLUGIN);
}

std::unordered_set<std::string> libsinsp::events::get_events_names(const std::unordered_set<ppm_event_code>& events_set)
{
	std::unordered_set<std::string> events_names_set;
	for(const auto& it : events_set)
	{
		if (it > PPME_GENERIC_X)
		{
			events_names_set.insert(g_infotables.m_event_info[it].name);
		}
		else
		{
			for (uint32_t i = 1; i < PPM_SC_MAX; i++)
			{
				const auto evts = get_event_set_from_ppm_sc_set({(ppm_sc_code)i});
				if (evts.find(it) != evts.end())
				{
					events_names_set.insert(g_infotables.m_syscall_info_table[i].name);
				}
			}
		}
	}
	return events_names_set;
}
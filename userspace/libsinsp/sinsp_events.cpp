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

std::unordered_set<std::string> libsinsp::events::event_set_to_names(const libsinsp::events::set<ppm_event_code>& events_set)
{
	std::unordered_set<std::string> events_names_set;
	events_set.for_each([&events_names_set](ppm_event_code val) {
		if (val > PPME_GENERIC_X)
		{
			events_names_set.insert(g_infotables.m_event_info[val].name);
		}
		else
		{
			// Skip unknown
			for (uint32_t i = 1; i < PPM_SC_MAX; i++)
			{
				auto single_ev_set = libsinsp::events::set<ppm_sc_code>();
				single_ev_set.insert((ppm_sc_code)i);
				const auto evts = sc_set_to_event_set(single_ev_set);
				if (evts.contains(val))
				{
					events_names_set.insert(g_infotables.m_syscall_info_table[i].name);
				}
			}
		}
		return true;
	});
	return events_names_set;
}

libsinsp::events::set<ppm_event_code> libsinsp::events::sinsp_state_event_set()
{
	static libsinsp::events::set<ppm_event_code> ppm_event_info_of_interest;
	if (ppm_event_info_of_interest.empty())
	{
		/* Fill-up the set of event infos of interest. This is needed to ensure critical non syscall PPME events are activated, e.g. container or proc exit events. */
		for(uint32_t ev = 2; ev < PPM_EVENT_MAX; ev++)
		{
			if(!libsinsp::events::is_old_version_event((ppm_event_code)ev) && !libsinsp::events::is_unused_event((ppm_event_code)ev) && !libsinsp::events::is_unknown_event((ppm_event_code)ev))
			{
				/* So far we only covered syscalls, so we add other kinds of
				interesting events. In this case, we are also interested in
				metaevents and in the procexit tracepoint event. */
				if(libsinsp::events::is_metaevent((ppm_event_code)ev) || ev == PPME_PROCEXIT_1_E)
				{
					ppm_event_info_of_interest.insert((ppm_event_code)ev);
				}
			}
		}
	}
	return ppm_event_info_of_interest;
}
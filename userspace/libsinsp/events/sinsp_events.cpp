#include "sinsp_events.h"

const ppm_event_info* libsinsp::events::info(ppm_event_code event_type)
{
	ASSERT(event_type < PPM_EVENT_MAX);
	return scap_get_event_info_table() + ((size_t) event_type);
}

bool libsinsp::events::is_generic(ppm_event_code event_type)
{
	ASSERT(event_type < PPM_EVENT_MAX);
	return event_type == ppm_event_code::PPME_GENERIC_E
		|| event_type == ppm_event_code::PPME_GENERIC_X;
}

bool libsinsp::events::is_unused_event(ppm_event_code event_type)
{
	ASSERT(event_type < PPM_EVENT_MAX);
	enum ppm_event_flags flags = scap_get_event_info_table()[event_type].flags;
	return (flags & EF_UNUSED);
}

bool libsinsp::events::is_skip_parse_reset_event(ppm_event_code event_type)
{
	ASSERT(event_type < PPM_EVENT_MAX);
	enum ppm_event_flags flags = scap_get_event_info_table()[event_type].flags;
	return (flags & EF_SKIPPARSERESET);
}

bool libsinsp::events::is_old_version_event(ppm_event_code event_type)
{
	ASSERT(event_type < PPM_EVENT_MAX);
	enum ppm_event_flags flags = scap_get_event_info_table()[event_type].flags;
	return (flags & EF_OLD_VERSION);
}

bool libsinsp::events::is_syscall_event(ppm_event_code event_type)
{
	ASSERT(event_type < PPM_EVENT_MAX);
	enum ppm_event_category category = scap_get_event_info_table()[event_type].category;
	return (category & EC_SYSCALL);
}

bool libsinsp::events::is_tracepoint_event(ppm_event_code event_type)
{
	ASSERT(event_type < PPM_EVENT_MAX);
	enum ppm_event_category category = scap_get_event_info_table()[event_type].category;
	return (category & EC_TRACEPOINT);
}

bool libsinsp::events::is_metaevent(ppm_event_code event_type)
{
	ASSERT(event_type < PPM_EVENT_MAX);
	enum ppm_event_category category = scap_get_event_info_table()[event_type].category;
	return (category & EC_METAEVENT);
}

bool libsinsp::events::is_unknown_event(ppm_event_code event_type)
{
	ASSERT(event_type < PPM_EVENT_MAX);
	enum ppm_event_category category = scap_get_event_info_table()[event_type].category;
	/* Please note this is not an `&` but an `==` if one event has
	 * the `EC_UNKNOWN` category, it must have only this category!
	 */
	return (category == EC_UNKNOWN);
}

bool libsinsp::events::is_plugin_event(ppm_event_code event_type)
{
	ASSERT(event_type < PPM_EVENT_MAX);
	enum ppm_event_category category = scap_get_event_info_table()[event_type].category;
	return (category & EC_PLUGIN);
}

std::unordered_set<std::string> libsinsp::events::event_set_to_names(const libsinsp::events::set<ppm_event_code>& events_set)
{
	std::unordered_set<std::string> events_names_set;
	for (const auto& val : events_set)
	{
		if (!libsinsp::events::is_generic(val))
		{
			events_names_set.insert(scap_get_event_info_table()[val].name);
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
					events_names_set.insert(scap_get_syscall_info_table()[i].name);
				}
			}
		}
	}
	return events_names_set;
}

libsinsp::events::set<ppm_event_code> libsinsp::events::names_to_event_set(const std::unordered_set<std::string>& events)
{
	std::unordered_set<std::string> remaining_events = events;
	libsinsp::events::set<ppm_event_code> ppm_event_set;

	// Main loop, on events (ie: non generic events)
	for (int ppm_ev = 2; ppm_ev < PPM_EVENT_MAX; ++ppm_ev)
	{
		const char* ppm_ev_name = scap_get_event_info_table()[ppm_ev].name;
		if (events.find(ppm_ev_name) != events.end())
		{
			ppm_event_set.insert((ppm_event_code)ppm_ev);
			remaining_events.erase(ppm_ev_name);
		}
	}

	// Only if there are some leftover events:
	// try to find a ppm_sc name that matches the event,
	// to eventually enable generic events too!
	if (!remaining_events.empty())
	{
		// Secondary loop, on syscalls and remaining events
		for(int ppm_sc = 0; ppm_sc < PPM_SC_MAX; ++ppm_sc)
		{
			const char* ppm_sc_name = scap_get_syscall_info_table()[ppm_sc].name;
			if(remaining_events.find(ppm_sc_name) != remaining_events.end())
			{
				ppm_event_set.insert(PPME_GENERIC_E);
				ppm_event_set.insert(PPME_GENERIC_X);
				break;
			}
		}
	}
	return ppm_event_set;
}

libsinsp::events::set<ppm_event_code> libsinsp::events::all_event_set()
{
	static libsinsp::events::set<ppm_event_code> ppm_event_set;
	if (ppm_event_set.empty())
	{
		for(uint32_t ppm_ev = 0; ppm_ev < PPM_EVENT_MAX; ppm_ev++)
		{
			ppm_event_set.insert((ppm_event_code)ppm_ev);
		}
	}
	return ppm_event_set;
}

libsinsp::events::set<ppm_sc_code> libsinsp::events::event_set_to_sc_set(const set<ppm_event_code>& events_of_interest)
{
	libsinsp::events::set<ppm_sc_code> ppm_sc_set;
	if(scap_get_ppm_sc_from_events(events_of_interest.data(), ppm_sc_set.data()) != SCAP_SUCCESS)
	{
		throw sinsp_exception("`ppm_sc_set` or `events_array` is an unexpected NULL vector!");
	}
	return ppm_sc_set;
}

libsinsp::events::set<ppm_event_code> libsinsp::events::sinsp_state_event_set()
{
	static libsinsp::events::set<ppm_event_code> ppm_event_info_of_interest;
	if (ppm_event_info_of_interest.empty())
	{
		ppm_event_info_of_interest = sc_set_to_event_set(sinsp_state_sc_set());
		/*
		 * Fill-up the set of event infos of interest.
		 * This is needed to ensure critical non syscall PPME events are activated,
		 * e.g. container or proc exit events.
		 * Skip generic events.
		 */
		for(uint32_t ev = 2; ev < PPM_EVENT_MAX; ev++)
		{
			if(!libsinsp::events::is_old_version_event((ppm_event_code)ev)
				&& !libsinsp::events::is_unused_event((ppm_event_code)ev)
				&& !libsinsp::events::is_unknown_event((ppm_event_code)ev))
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
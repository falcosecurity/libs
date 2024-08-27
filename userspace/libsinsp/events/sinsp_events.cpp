#include <libsinsp/events/sinsp_events.h>
#include <libsinsp/utils.h>

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
	ppm_event_flags flags = scap_get_event_info_table()[event_type].flags;
	return (flags & EF_UNUSED);
}

bool libsinsp::events::is_skip_parse_reset_event(ppm_event_code event_type)
{
	ASSERT(event_type < PPM_EVENT_MAX);
	ppm_event_flags flags = scap_get_event_info_table()[event_type].flags;
	return (flags & EF_SKIPPARSERESET);
}

bool libsinsp::events::is_old_version_event(ppm_event_code event_type)
{
	ASSERT(event_type < PPM_EVENT_MAX);
	ppm_event_flags flags = scap_get_event_info_table()[event_type].flags;
	return (flags & EF_OLD_VERSION);
}

bool libsinsp::events::is_syscall_event(ppm_event_code event_type)
{
	ASSERT(event_type < PPM_EVENT_MAX);
	ppm_event_category category = scap_get_event_info_table()[event_type].category;
	return (category & EC_SYSCALL);
}

bool libsinsp::events::is_tracepoint_event(ppm_event_code event_type)
{
	ASSERT(event_type < PPM_EVENT_MAX);
	ppm_event_category category = scap_get_event_info_table()[event_type].category;
	return (category & EC_TRACEPOINT);
}

bool libsinsp::events::is_metaevent(ppm_event_code event_type)
{
	ASSERT(event_type < PPM_EVENT_MAX);
	ppm_event_category category = scap_get_event_info_table()[event_type].category;
	return (category & EC_METAEVENT);
}

bool libsinsp::events::is_unknown_event(ppm_event_code event_type)
{
	ASSERT(event_type < PPM_EVENT_MAX);
	ppm_event_category category = scap_get_event_info_table()[event_type].category;
	/* Please note this is not an `&` but an `==` if one event has
	 * the `EC_UNKNOWN` category, it must have only this category!
	 */
	return (category == EC_UNKNOWN);
}

bool libsinsp::events::is_plugin_event(ppm_event_code event_type)
{
	ASSERT(event_type < PPM_EVENT_MAX);
	ppm_event_category category = scap_get_event_info_table()[event_type].category;
	return (category & EC_PLUGIN);
}

std::unordered_set<std::string> libsinsp::events::event_set_to_names(const libsinsp::events::set<ppm_event_code>& events_set, bool resolve_generic)
{
	bool resolved_generic = false;
	std::unordered_set<std::string> events_names_set;
	for (const auto& ev : events_set)
	{
		if (libsinsp::events::is_generic(ev))
		{
			if (resolve_generic && !resolved_generic)
			{
				/* note: using existing ppm sc APIs and generic set operations to minimize new logic that requires maintenance beyond what we already have. */
				auto sc_set = libsinsp::events::event_set_to_sc_set(libsinsp::events::set<ppm_event_code>{PPME_GENERIC_E, PPME_GENERIC_X});
				events_names_set = unordered_set_union(libsinsp::events::sc_set_to_sc_names(sc_set), events_names_set);
				events_names_set.erase("unknown"); // not needed
				resolved_generic = true;
			}
		}
		else
		{
			events_names_set.insert(scap_get_event_info_table()[ev].name);
		}
	}
	return events_names_set;
}

// todo(jasondellaluce): think about how we can handle well PPME_ASYNCEVENT_E
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
			const char* ppm_sc_name = scap_get_ppm_sc_name((ppm_sc_code)ppm_sc);
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
	std::vector<uint8_t> sc_vec(PPM_SC_MAX);
	if(scap_get_ppm_sc_from_events(events_of_interest.data(), sc_vec.data()) != SCAP_SUCCESS)
	{
		throw sinsp_exception("`ppm_sc_set` or `events_array` is an unexpected NULL vector!");
	}
	for (int i = 0; i < PPM_SC_MAX; i++)
	{
		if (sc_vec[i])
		{
			ppm_sc_set.insert((ppm_sc_code)i);
		}
	}
	return ppm_sc_set;
}

/// todo(@Andreagit97): we need to decide if we want to keep this API
libsinsp::events::set<ppm_event_code> libsinsp::events::sinsp_state_event_set()
{
	static libsinsp::events::set<ppm_event_code> ppm_event_info_of_interest;
	if (ppm_event_info_of_interest.empty())
	{
		ppm_event_info_of_interest = sc_set_to_event_set(sinsp_state_sc_set());
		/*
		 * Fill-up the set of event infos of interest.
		 * This is needed to ensure critical non syscall/tracepoint PPME events are activated,
		 * e.g. container
		 * Skip generic events.
		 */
		for(uint32_t ev = 2; ev < PPM_EVENT_MAX; ev++)
		{
			if(!libsinsp::events::is_unused_event((ppm_event_code)ev)
				&& !libsinsp::events::is_unknown_event((ppm_event_code)ev))
			{
				/* So far we only covered syscalls, so we need to add
				 * other kinds of metaevents.
				 */
				if(libsinsp::events::is_metaevent((ppm_event_code)ev))
				{
					ppm_event_info_of_interest.insert((ppm_event_code)ev);
				}
			}
		}
	}
	return ppm_event_info_of_interest;
}

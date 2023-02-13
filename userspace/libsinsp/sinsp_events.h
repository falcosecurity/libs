#pragma once

#include "event.h"
#include <utils.h>
#include <sinsp_exception.h>
#include <sinsp_public.h>
#include <unordered_set>
#include <string>
#include <vector>
#include <functional>

// The following are needed on MacOS to be able to
// initialize a std::(unordered)map/set<ppm_X_code>{}
namespace std
{
template<>
struct hash<ppm_sc_code> {
	size_t operator()(const ppm_sc_code &pt) const {
		return std::hash<uint32_t>()((uint32_t)pt);
	}
};

template<>
struct hash<ppm_tp_code> {
	size_t operator()(const ppm_tp_code &pt) const {
		return std::hash<uint32_t>()((uint32_t)pt);
	}
};

template<>
struct hash<ppm_event_code> {
	size_t operator()(const ppm_event_code &pt) const {
		return std::hash<uint32_t>()((uint32_t)pt);
	}
};
}

namespace libsinsp {
namespace events {

template<typename ppm_type>
class set
{
private:
	using vec_t = std::vector<uint8_t>;
	vec_t m_types{};
	ppm_type max;
	size_t len;

	inline void check_range(ppm_type e) const
	{
		if(e > max)
		{
			throw sinsp_exception("invalid event type");
		}
	}

public:
	set(set&&)  noexcept = default;
	set(const set&) = default;
	set& operator=(set&&)  noexcept = default;
	set& operator=(const set&) = default;
	set<ppm_type>() = delete;

	inline explicit set(ppm_type maxLen):
		m_types(maxLen + 1, 0),
		max(maxLen),
		len(0)
	{
	}

	static set from_unordered_set(std::unordered_set<ppm_type> u_set)
	{
		set<ppm_type> ret;
		for (const auto &val : u_set)
		{
			ret.insert(val);
		}
		return ret;
	}

	inline void insert(ppm_type e)
	{
		check_range(e);
		m_types[e] = 1;
		len++;
	}

	inline void remove(ppm_type e)
	{
		check_range(e);
		m_types[e] = 0;
		len--;
	}

	inline bool contains(ppm_type e) const
	{
		check_range(e);
		return m_types[e] != 0;
	}

	void clear()
	{
		for(auto& v : m_types)
		{
			v = 0;
		}
		len = 0;
	}

	inline bool empty() const
	{
		return len == 0;
	}

	inline size_t size() const
	{
		return len;
	}

	bool equals(const set& other) const
	{
		return m_types == other.m_types;
	}

	set merge(const set& other) const
	{
		if (other.max != max)
		{
			throw sinsp_exception("cannot merge sets with different max size.");
		}
		set<ppm_type> ret(max);
		for(size_t i = 0; i <= max; ++i)
		{
			if (!m_types[i] && other.m_types[i])
			{
				ret.insert((ppm_type)i);
			}
		}
		return ret;
	}

	set diff(const set& other) const
	{
		if (other.max != max)
		{
			throw sinsp_exception("cannot diff sets with different max size.");
		}
		set<ppm_type> ret(max);
		for(size_t i = 0; i <= max; ++i)
		{
			if (m_types[i] ^ other.m_types[i])
			{
				ret.insert((ppm_type)i);
			}
		}
		return ret;
	}

	set intersect(const set& other) const
	{
		if (other.max != max)
		{
			throw sinsp_exception("cannot intersect sets with different max size.");
		}
		set<ppm_type> ret(max);
		for(size_t i = 0; i <= max; ++i)
		{
			if (m_types[i] & other.m_types[i])
			{
				ret.insert((ppm_type)i);
			}
		}
		return ret;
	}

	// This should be union but it is a reserved name
	set add(const set& other) const
	{
		if (other.max != max)
		{
			throw sinsp_exception("cannot union sets with different max size.");
		}
		set<ppm_type> ret(max);
		for(size_t i = 0; i <= max; ++i)
		{
			if (m_types[i] | other.m_types[i])
			{
				ret.insert((ppm_type)i);
			}
		}
		return ret;
	}

	void for_each(const std::function<bool(ppm_type)>& consumer) const
	{
		for(size_t i = 0; i < max; ++i)
		{
			if(m_types[i] != 0)
			{
				if(!consumer((ppm_type)i))
				{
					return;
				}
			}
		}
	}
};

// Some template specialization for useful constructors

template <>
inline set<ppm_sc_code>::set() : set(PPM_SC_MAX)
{
}

template<>
inline set<ppm_event_code>::set(): set(PPM_EVENT_MAX)
{
}

template<>
inline set<ppm_tp_code>::set(): set(TP_VAL_MAX)
{
}


/*=============================== Events related ===============================*/

/**
	 * @brief If the event type has one of the following flags return true:
	 * - `EF_UNUSED`
	 *
	 * @param event_type type of event we want to check (must be less than `PPM_EVENT_MAX`)
	 * @return true if the event type has at least one of these flags.
 */
bool is_unused_event(ppm_event_code event_type);

/**
	 * @brief If the event type has one of the following flags return true:
	 * - `EF_SKIPPARSERESET`
	 *
	 * @param event_type type of event we want to check (must be less than `PPM_EVENT_MAX`)
	 * @return true if the event type has at least one of these flags.
 */
bool is_skip_parse_reset_event(ppm_event_code event_type);

/**
	 * @brief Return true if the event has the `EF_OLD_VERSION` flag
	 *
	 * @param event_type type of event we want to check (must be less than `PPM_EVENT_MAX`)
	 * @return true if the event type has the `EF_OLD_VERSION` flag.
 */
bool is_old_version_event(ppm_event_code event_type);

/**
	 * @brief Return true if the event belongs to the `EC_SYSCALL` category
	 *
	 * @param event_type type of event we want to check (must be less than `PPM_EVENT_MAX`)
	 * @return true if the event type has the `EC_SYSCALL` category.
 */
bool is_syscall_event(ppm_event_code event_type);

/**
	 * @brief Return true if the event belongs to the `EC_TRACEPOINT` category
	 *
	 * @param event_type type of event we want to check (must be less than `PPM_EVENT_MAX`)
	 * @return true if the event type has the `EC_TRACEPOINT` category.
 */
bool is_tracepoint_event(ppm_event_code event_type);

/**
	 * @brief Return true if the event belongs to the `EC_METAEVENT` category
	 *
	 * @param event_type type of event we want to check (must be less than `PPM_EVENT_MAX`)
	 * @return true if the event type has the `EC_METAEVENT` category.
 */
bool is_metaevent(ppm_event_code event_type);

/**
	 * @brief Return true if the event belongs to the `EC_UNKNOWN` category
	 *
	 * @param event_type type of event we want to check (must be less than `PPM_EVENT_MAX`)
	 * @return true if the event type has the `EC_UNKNOWN` category.
 */
bool is_unknown_event(ppm_event_code event_type);

/**
	 * @brief Return true if the event belongs to the `EC_PLUGIN` category
	 *
	 * @param event_type type of event we want to check (must be less than `PPM_EVENT_MAX`)
	 * @return true if the event type has the `EC_PLUGIN` category.
 */
bool is_plugin_event(ppm_event_code event_type);

/*=============================== Events related ===============================*/

/*=============================== PPM_SC set related (ppm_sc.cpp) ===============================*/

/*!
	\brief Provide the minimum set of syscalls required by `libsinsp` state collection.
	If you call it without arguments it returns a new set with just these syscalls
	otherwise, it merges the minimum set of syscalls with the one you provided.

	WARNING: without using this method, we cannot guarantee that `libsinsp` state
	will always be up to date, or even work at all.
*/
set<ppm_sc_code> enforce_sinsp_state_ppm_sc(set<ppm_sc_code> ppm_sc_of_interest = {});

/*!
  \brief Enforce simple set of syscalls with all the security-valuable syscalls.
  It has same effect of old `simple_consumer` mode.
  Does enforce minimum sinsp state set.
*/
set<ppm_sc_code> enforce_simple_ppm_sc_set(set<ppm_sc_code> ppm_sc_set = {});

/*!
  \brief Enforce passed set of syscalls with the ones
  valuable for IO (EC_IO_READ, EC_IO_WRITE).
  Does not enforce minimum sinsp state set.
*/
set<ppm_sc_code> enforce_io_ppm_sc_set(set<ppm_sc_code> ppm_sc_set = {});

/*!
  \brief Enforce passed set of syscalls with the ones
  valuable for IO (EC_IO_OTHER).
  Does not enforce minimum sinsp state set.
*/
set<ppm_sc_code> enforce_io_other_ppm_sc_set(set<ppm_sc_code> ppm_sc_set = {});

/*!
  \brief Enforce passed set of syscalls with the ones
  valuable for file operations.
  Does not enforce minimum sinsp state set.
*/
set<ppm_sc_code> enforce_file_ppm_sc_set(set<ppm_sc_code> ppm_sc_set = {});

/*!
  \brief Enforce passed set of syscalls with the ones
  valuable for networking.
  Does not enforce minimum sinsp state set.
*/
set<ppm_sc_code> enforce_net_ppm_sc_set(set<ppm_sc_code> ppm_sc_set = {});

/*!
  \brief Enforce passed set of syscalls with the ones
  valuable for process state tracking.
  Does not enforce minimum sinsp state set.
*/
set<ppm_sc_code> enforce_proc_ppm_sc_set(set<ppm_sc_code> ppm_sc_set = {});

/*!
  \brief Enforce passed set of syscalls with the ones
  valuable for system state tracking (signals, memory...)
  Does not enforce minimum sinsp state set.
*/
set<ppm_sc_code> enforce_sys_ppm_sc_set(set<ppm_sc_code> ppm_sc_set = {});

/*!
  \brief Enforce passed set of events with critical non syscalls events,
  e.g. container or procexit events.
*/
set<ppm_event_code> enforce_sinsp_state_ppme(set<ppm_event_code> ppm_event_info_of_interest = {});

/*!
  \brief Get all the available ppm_sc.
  Does enforce minimum sinsp state set.
*/
set<ppm_sc_code> get_all_ppm_sc();

/*!
  \brief Get the name of all the ppm_sc provided in the set.
*/
std::unordered_set<std::string> get_ppm_sc_names(const set<ppm_sc_code>& ppm_sc_set);

/*!
  \brief Get the name of all the events provided in the set.
*/
std::unordered_set<std::string> get_events_names(const set<ppm_event_code>& events_set);

/*!
  \brief Get the ppm_sc of all the syscalls names provided in the set.
*/
set<ppm_sc_code> get_ppm_sc_set_from_syscalls_name(const std::unordered_set<std::string>& syscalls);

/**
	 * @brief When you want to retrieve the events associated with a particular `ppm_sc` you have to
	 * pass a single-element set, with just the specific `ppm_sc`. On the other side, you want all the events
	 * associated with a set of `ppm_sc` you have to pass the entire set of `ppm_sc`.
	 *
	 * @param ppm_sc_set set of `ppm_sc` from which you want to obtain information
	 * @return set of events associated with the provided `ppm_sc` set.
 */
set<ppm_event_code> get_event_set_from_ppm_sc_set(const set<ppm_sc_code> &ppm_sc_of_interest);

/*=============================== PPM_SC set related (ppm_sc.cpp) ===============================*/

/*=============================== Tracepoint set related ===============================*/

/*!
  \brief Get all the available tracepoints.
*/
set<ppm_tp_code> get_all_tp();

/*!
  \brief Get the name of all the ppm_sc provided in the set.
*/
std::unordered_set<std::string> get_tp_names(const set<ppm_tp_code>& tp_set);

/*!
	\brief Provide the minimum set of tracepoints required by `libsinsp` state collection.
	If you call it without arguments it returns a new set with just these tracepoints
	otherwise, it merges the minimum set of tracepoints with the one you provided.

	WARNING: without using this method, we cannot guarantee that `libsinsp` state
	will always be up to date, or even work at all.
*/
set<ppm_tp_code> enforce_sinsp_state_tp(set<ppm_tp_code> tp_of_interest = {});

/*=============================== Tracepoint set related ===============================*/

}
}
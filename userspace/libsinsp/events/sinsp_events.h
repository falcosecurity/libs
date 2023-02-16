/*
Copyright (C) 2023 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#pragma once

#include "sinsp_events_set.h"

#include <unordered_set>
#include <string>

namespace libsinsp {
namespace events {

/*=============================== Events related ===============================*/

/**
	 * @brief Returns the static information of the event.
	 *
	 * @param event_type type of event we want to retrieve info for (must be less than `PPM_EVENT_MAX`)
	 * @return const ppm_event_info* the info entry of the event.
 */
const ppm_event_info* info(ppm_event_code event_type);

/**
	 * @brief Return true if the event is generic.
	 *
	 * @param event_type type of event we want to check (must be less than `PPM_EVENT_MAX`)
	 * @return true if the event type is generic.
 */
bool is_generic(ppm_event_code event_type);

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

/*=============================== PPM_SC set related (sinsp_events_ppm_sc.cpp) ===============================*/

/*!
	\brief Provide the minimum set of syscalls required by `libsinsp` state collection.

	WARNING: without merging your ppm_sc set with the one provided by this method,
 	we cannot guarantee that `libsinsp` state will always be up to date, or even work at all.
*/
set<ppm_sc_code> sinsp_state_sc_set();

/*!
  \brief Enforce simple set of syscalls with all the security-valuable syscalls.
  It has same effect of old `simple_consumer` mode.
  Does enforce minimum sinsp state set.
*/
set<ppm_sc_code> enforce_simple_sc_set(set<ppm_sc_code> ppm_sc_set = {});

/*!
  \brief Returns set of syscalls
  valuable for IO (EC_IO_READ, EC_IO_WRITE).
*/
set<ppm_sc_code> io_sc_set();

/*!
  \brief Returns set of syscalls
  valuable for IO (EC_IO_OTHER).
*/
set<ppm_sc_code> io_other_sc_set();

/*!
  \brief Returns set of syscalls
  valuable for file operations.
*/
set<ppm_sc_code> file_sc_set();

/*!
  \brief Returns set of syscalls
  valuable for networking.
*/
set<ppm_sc_code> net_sc_set();

/*!
  \brief Returns set of syscalls
  valuable for process state tracking.
*/
set<ppm_sc_code> proc_sc_set();

/*!
  \brief Returns set of syscalls
  valuable for system state tracking (signals, memory...)
*/
set<ppm_sc_code> sys_sc_set();

/*!
  \brief Get all the available ppm_sc.
*/
set<ppm_sc_code> all_sc_set();

/*!
  \brief Get the name of all the ppm_sc provided in the set.
*/
std::unordered_set<std::string> sc_set_to_names(const set<ppm_sc_code>& ppm_sc_set);

/*!
  \brief Get the ppm_sc of all the syscalls names provided in the set.
*/
set<ppm_sc_code> names_to_sc_set(const std::unordered_set<std::string>& syscalls);

/**
	 * @brief When you want to retrieve the events associated with a particular `ppm_sc` you have to
	 * pass a single-element set, with just the specific `ppm_sc`. On the other side, you want all the events
	 * associated with a set of `ppm_sc` you have to pass the entire set of `ppm_sc`.
	 *
	 * @param ppm_sc_set set of `ppm_sc` from which you want to obtain information
	 * @return set of events associated with the provided `ppm_sc` set.
 */
set<ppm_event_code> sc_set_to_event_set(const set<ppm_sc_code> &ppm_sc_of_interest);

/*=============================== PPM_SC set related (sinsp_events_ppm_sc.cpp) ===============================*/

/*=============================== PPME set related (sinsp_events.cpp) ===============================*/

/*!
  \brief Get all the available ppm_event.
*/
set<ppm_event_code> all_event_set();

/*!
  \brief Returns set of events with critical non syscalls events,
  e.g. container or procexit events.
*/
set<ppm_event_code> sinsp_state_event_set();

/*!
  \brief Get the name of all the events provided in the set.
*/
std::unordered_set<std::string> event_set_to_names(const set<ppm_event_code>& events_set);

/*!
  \brief Get the ppm_event of all the event names provided in the set.
*/
set<ppm_event_code> names_to_event_set(const std::unordered_set<std::string>& events);

/**
	 * @brief When you want to retrieve the events associated with a particular `ppm_sc` you have to
	 * pass a single-element set, with just the specific `ppm_sc`. On the other side, you want all the events
	 * associated with a set of `ppm_sc` you have to pass the entire set of `ppm_sc`.
	 *
	 * @param ppm_sc_set set of `ppm_sc` from which you want to obtain information
	 * @return set of events associated with the provided `ppm_sc` set.
 */
set<ppm_sc_code> event_set_to_sc_set(const set<ppm_event_code> &events_of_interest);

/*=============================== PPME set related (sinsp_events.cpp) ===============================*/

} // events
} // libsinsp
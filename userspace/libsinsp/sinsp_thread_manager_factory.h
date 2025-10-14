// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2025 The Falco Authors.

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
#include <libsinsp/thread_manager.h>

/*!
  \brief Factory hiding sinsp_thread_manager creation details.
*/
class sinsp_thread_manager_factory {
	const sinsp_mode& m_sinsp_mode;
	const sinsp_threadinfo_factory& m_threadinfo_factory;
	sinsp_observer* const& m_observer;
	const std::shared_ptr<const sinsp_plugin>& m_input_plugin;
	const bool& m_large_envs_enabled;
	const timestamper& m_timestamper;
	const int64_t& m_sinsp_pid;
	const uint64_t& m_threads_purging_scan_time_ns;
	const uint64_t& m_thread_timeout_ns;
	std::shared_ptr<sinsp_stats_v2> m_sinsp_stats_v2;
	scap_platform* const& m_scap_platform;
	scap_t* const& m_scap_handle;
	const std::shared_ptr<libsinsp::state::dynamic_struct::field_infos>&
	        m_thread_manager_dyn_fields;
	const std::shared_ptr<libsinsp::state::dynamic_struct::field_infos>& m_fdtable_dyn_fields;
	const std::shared_ptr<sinsp_usergroup_manager>& m_usergroup_manager;

public:
	sinsp_thread_manager_factory(
	        const sinsp_mode& sinsp_mode,
	        const sinsp_threadinfo_factory& threadinfo_factory,
	        sinsp_observer* const& observer,
	        const std::shared_ptr<const sinsp_plugin>& input_plugin,
	        const bool& large_envs_enabled,
	        const timestamper& timestamper,
	        const int64_t& sinsp_pid,
	        const uint64_t& threads_purging_scan_time_ns,
	        const uint64_t& thread_timeout_ns,
	        const std::shared_ptr<sinsp_stats_v2>& sinsp_stats_v2,
	        scap_platform* const& scap_platform,
	        scap_t* const& scap_handle,
	        const std::shared_ptr<libsinsp::state::dynamic_struct::field_infos>&
	                thread_manager_dyn_fields,
	        const std::shared_ptr<libsinsp::state::dynamic_struct::field_infos>& fdtable_dyn_fields,
	        const std::shared_ptr<sinsp_usergroup_manager>& usergroup_manager):
	        m_sinsp_mode{sinsp_mode},
	        m_threadinfo_factory{threadinfo_factory},
	        m_observer{observer},
	        m_input_plugin{input_plugin},
	        m_large_envs_enabled{large_envs_enabled},
	        m_timestamper{timestamper},
	        m_sinsp_pid{sinsp_pid},
	        m_threads_purging_scan_time_ns{threads_purging_scan_time_ns},
	        m_thread_timeout_ns{thread_timeout_ns},
	        m_sinsp_stats_v2{sinsp_stats_v2},
	        m_scap_platform{scap_platform},
	        m_scap_handle{scap_handle},
	        m_thread_manager_dyn_fields{thread_manager_dyn_fields},
	        m_fdtable_dyn_fields{fdtable_dyn_fields},
	        m_usergroup_manager(usergroup_manager) {}

	std::shared_ptr<sinsp_thread_manager> create() const {
		return std::make_unique<sinsp_thread_manager>(m_sinsp_mode,
		                                              m_threadinfo_factory,
		                                              m_observer,
		                                              m_input_plugin,
		                                              m_large_envs_enabled,
		                                              m_timestamper,
		                                              m_sinsp_pid,
		                                              m_threads_purging_scan_time_ns,
		                                              m_thread_timeout_ns,
		                                              m_sinsp_stats_v2,
		                                              m_scap_platform,
		                                              m_scap_handle,
		                                              m_thread_manager_dyn_fields,
		                                              m_fdtable_dyn_fields,
		                                              m_usergroup_manager);
	}
};

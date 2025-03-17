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
#include <libsinsp/sinsp_mode.h>
#include <libsinsp/sinsp_fdinfo_factory.h>
#include <libsinsp/fdtable.h>

struct sinsp_stats_v2;

/*!
  \brief Factory hiding sinsp_fdtable creation details.
*/
class sinsp_fdtable_factory {
	const sinsp_mode& m_sinsp_mode;
	const uint32_t m_max_table_size;
	const sinsp_fdinfo_factory& m_fdinfo_factory;
	const std::shared_ptr<const sinsp_plugin>& m_input_plugin;
	const std::shared_ptr<sinsp_stats_v2> m_sinsp_stats_v2;
	scap_platform* const* m_scap_platform;

public:
	sinsp_fdtable_factory(const sinsp_mode& sinsp_mode,
	                      const uint32_t max_table_size,
	                      const sinsp_fdinfo_factory& fdinfo_factory,
	                      const std::shared_ptr<const sinsp_plugin>& input_plugin,
	                      const std::shared_ptr<sinsp_stats_v2>& sinsp_stats_v2,
	                      scap_platform* const* scap_platform):
	        m_sinsp_mode{sinsp_mode},
	        m_max_table_size{max_table_size},
	        m_fdinfo_factory{fdinfo_factory},
	        m_input_plugin{input_plugin},
	        m_sinsp_stats_v2{sinsp_stats_v2},
	        m_scap_platform{scap_platform} {}

	sinsp_fdtable create() const {
		return sinsp_fdtable{m_sinsp_mode,
		                     m_max_table_size,
		                     m_fdinfo_factory,
		                     m_input_plugin,
		                     m_sinsp_stats_v2,
		                     m_scap_platform};
	}
};

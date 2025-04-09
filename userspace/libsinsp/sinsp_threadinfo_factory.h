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
#include <libsinsp/sinsp_external_processor.h>
#include <libsinsp/threadinfo.h>

/*!
  \brief Factory hiding sinsp_threadinfo creation details.
*/
class sinsp_threadinfo_factory {
	sinsp* m_sinsp;
	libsinsp::event_processor* const& m_external_event_processor;
	const std::shared_ptr<libsinsp::state::dynamic_struct::field_infos>&m_thread_manager_dyn_fields,
	        m_fdtable_dyn_fields;
	const sinsp_fdinfo_factory& m_fdinfo_factory;
	const sinsp_fdtable_factory& m_fdtable_factory;

public:
	sinsp_threadinfo_factory(
	        sinsp* sinsp,
	        libsinsp::event_processor* const& external_event_processor,
	        const std::shared_ptr<libsinsp::state::dynamic_struct::field_infos>&
	                thread_manager_dyn_fields,
	        const std::shared_ptr<libsinsp::state::dynamic_struct::field_infos>& fdtable_dyn_fields,
	        const sinsp_fdinfo_factory& fdinfo_factory,
	        const sinsp_fdtable_factory& fdtable_factory):
	        m_sinsp{sinsp},
	        m_external_event_processor{external_event_processor},
	        m_thread_manager_dyn_fields{thread_manager_dyn_fields},
	        m_fdtable_dyn_fields{fdtable_dyn_fields},
	        m_fdinfo_factory{fdinfo_factory},
	        m_fdtable_factory{fdtable_factory} {}
	std::unique_ptr<sinsp_threadinfo> create() const {
		std::unique_ptr<sinsp_threadinfo> tinfo =
		        m_external_event_processor
		                ? m_external_event_processor->build_threadinfo(m_sinsp)
		                : std::make_unique<sinsp_threadinfo>(m_fdinfo_factory,
		                                                     m_fdtable_factory,
		                                                     m_sinsp,
		                                                     m_thread_manager_dyn_fields);
		if(tinfo->dynamic_fields() == nullptr) {
			tinfo->set_dynamic_fields(m_thread_manager_dyn_fields);
		}
		tinfo->get_fdtable().set_dynamic_fields(m_fdtable_dyn_fields);
		return tinfo;
	}

	std::shared_ptr<sinsp_threadinfo> create_shared() const {
		// create_shared is currently used in contexts not handled by any external event processor,
		// nor by any component needing dynamic fields to be initialized: for these reasons, for the
		// moment, it is just a simplified (shared) version of what `create` does.
		return std::make_shared<sinsp_threadinfo>(m_fdinfo_factory, m_fdtable_factory);
	}
};

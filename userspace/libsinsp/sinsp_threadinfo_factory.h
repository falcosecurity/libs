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
	libsinsp::event_processor** m_external_event_processor;
	const std::shared_ptr<libsinsp::state::dynamic_struct::field_infos>&m_thread_manager_dyn_fields,
	        m_fdtable_dyn_fields;
	const sinsp_fdinfo_factory& m_fdinfo_factory;

	libsinsp::event_processor* get_external_event_processor() const {
		return *m_external_event_processor;
	}

public:
	sinsp_threadinfo_factory(
	        sinsp* sinsp,
	        libsinsp::event_processor** external_event_processor,
	        const std::shared_ptr<libsinsp::state::dynamic_struct::field_infos>&
	                thread_manager_dyn_fields,
	        const std::shared_ptr<libsinsp::state::dynamic_struct::field_infos>& fdtable_dyn_fields,
	        const sinsp_fdinfo_factory& fdinfo_factory):
	        m_sinsp{sinsp},
	        m_external_event_processor{external_event_processor},
	        m_thread_manager_dyn_fields{thread_manager_dyn_fields},
	        m_fdtable_dyn_fields{fdtable_dyn_fields},
	        m_fdinfo_factory{fdinfo_factory} {}
	std::unique_ptr<sinsp_threadinfo> create() const {
		const auto external_event_processor = get_external_event_processor();
		std::unique_ptr<sinsp_threadinfo> tinfo =
		        external_event_processor
		                ? external_event_processor->build_threadinfo(m_sinsp)
		                : std::make_unique<sinsp_threadinfo>(m_fdinfo_factory,
		                                                     m_sinsp,
		                                                     m_thread_manager_dyn_fields);
		if(tinfo->dynamic_fields() == nullptr) {
			tinfo->set_dynamic_fields(m_thread_manager_dyn_fields);
		}
		tinfo->get_fdtable().set_dynamic_fields(m_fdtable_dyn_fields);
		return tinfo;
	}
};

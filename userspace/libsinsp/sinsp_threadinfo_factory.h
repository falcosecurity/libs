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

class sinsp;

/*!
  \brief Factory hiding sinsp_threadinfo creation details.
*/
class sinsp_threadinfo_factory {
	sinsp* m_sinsp;
	const std::shared_ptr<sinsp_threadinfo::ctor_params>& m_params;
	libsinsp::event_processor* const& m_external_event_processor;
	const std::shared_ptr<libsinsp::state::dynamic_struct::field_infos>& m_fdtable_dyn_fields;

	// `create_unique` is only provided in order to let an external event processor create a
	// threadinfo without tracking all the needed dependencies and, at the same time, avoiding code
	// repetition. The access is granted through the
	// `sinsp_threadinfo_factory::create_unique_attorney` class (see its definition for more
	// details).
	std::unique_ptr<sinsp_threadinfo> create_unique() const {
		return std::make_unique<sinsp_threadinfo>(m_params);
	}

public:
	/*!
	  \brief This class follows the attorney-client idiom to limit the access to
	  `sinsp_threadinfo_factory::create_unique()` only to `libsinsp::event_processor`.
	*/
	class create_unique_attorney {
		static std::unique_ptr<sinsp_threadinfo> create(sinsp_threadinfo_factory const& factory) {
			return factory.create_unique();
		}
		friend libsinsp::event_processor;
	};

	sinsp_threadinfo_factory(sinsp* sinsp,
	                         const std::shared_ptr<sinsp_threadinfo::ctor_params>& params,
	                         libsinsp::event_processor* const& external_event_processor,
	                         const std::shared_ptr<libsinsp::state::dynamic_struct::field_infos>&
	                                 fdtable_dyn_fields):
	        m_sinsp{sinsp},
	        m_params{params},
	        m_external_event_processor{external_event_processor},
	        m_fdtable_dyn_fields{fdtable_dyn_fields} {}

	std::unique_ptr<sinsp_threadinfo> create() const {
		std::unique_ptr<sinsp_threadinfo> tinfo =
		        m_external_event_processor ? m_external_event_processor->build_threadinfo(m_sinsp)
		                                   : create_unique();
		if(tinfo->dynamic_fields() == nullptr) {
			tinfo->set_dynamic_fields(m_params->thread_manager_dyn_fields);
		}
		tinfo->get_fdtable().set_dynamic_fields(m_fdtable_dyn_fields);
		return tinfo;
	}

	std::shared_ptr<sinsp_threadinfo> create_shared() const {
		// create_shared is currently used in contexts not handled by any external event processor,
		// nor by any component needing dynamic fields to be initialized: for these reasons, for the
		// moment, it is just a simplified (shared) version of what `create` does.
		return std::make_shared<sinsp_threadinfo>(m_params);
	}
};

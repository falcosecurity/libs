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

/*!
  \brief Factory hiding sinsp_fdinfo creation details.
*/
class sinsp_fdinfo_factory {
	sinsp* m_sinsp;
	libsinsp::event_processor** m_external_event_processor;
	const std::shared_ptr<libsinsp::state::dynamic_struct::field_infos>& m_dyn_fields;

	libsinsp::event_processor* get_external_event_processor() const {
		return *m_external_event_processor;
	}

	// The access to `create_unique` is granted through the
	// `sinsp_fdinfo_factory::create_unique_attorney` class (see its definition for more details).
	static std::unique_ptr<sinsp_fdinfo> create_unique() {
		return std::make_unique<sinsp_fdinfo>();
	}

public:
	/*!
	  \brief This class follows the attorney-client idiom to limit the access to
	  `sinsp_fdinfo_factory::create_unique()` only to `libsinsp::event_processor`.
	*/
	class create_unique_attorney {
		static std::unique_ptr<sinsp_fdinfo> create(sinsp_fdinfo_factory const& factory) {
			return factory.create_unique();
		}
		friend libsinsp::event_processor;
	};

	sinsp_fdinfo_factory(
	        sinsp* sinsp,
	        libsinsp::event_processor** external_event_processor,
	        const std::shared_ptr<libsinsp::state::dynamic_struct::field_infos>& dyn_fields):
	        m_sinsp{sinsp},
	        m_external_event_processor{external_event_processor},
	        m_dyn_fields{dyn_fields} {}

	std::unique_ptr<sinsp_fdinfo> create() const {
		const auto external_event_processor = get_external_event_processor();
		auto fdinfo = external_event_processor ? external_event_processor->build_fdinfo(m_sinsp)
		                                       : create_unique();
		if(fdinfo->dynamic_fields() == nullptr) {
			fdinfo->set_dynamic_fields(m_dyn_fields);
		}
		return fdinfo;
	}
};

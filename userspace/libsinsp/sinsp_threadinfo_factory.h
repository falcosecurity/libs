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
#include <libsinsp/sinsp_external_processor.h>

/*!
  \brief Factory hiding sinsp_fdinfo creation details.
*/
class sinsp_threadinfo_factory {
	sinsp* m_sinsp;
	std::shared_ptr<sinsp_thread_manager> m_thread_manager;
	libsinsp::event_processor** m_external_event_processor;

	libsinsp::event_processor* get_external_event_processor() const {
		return *m_external_event_processor;
	}

public:
	sinsp_threadinfo_factory(sinsp* sinsp,
	                         const std::shared_ptr<sinsp_thread_manager>& thread_manager,
	                         libsinsp::event_processor** external_event_processor):
	        m_sinsp{sinsp},
	        m_thread_manager{thread_manager},
	        m_external_event_processor{external_event_processor} {}
	std::unique_ptr<sinsp_threadinfo> create() const {
		const auto external_event_processor = get_external_event_processor();
		auto ret = external_event_processor ? external_event_processor->build_threadinfo(m_sinsp)
		                                    : m_thread_manager->new_threadinfo();
		m_thread_manager->set_tinfo_shared_dynamic_fields(*ret);
		return ret;
	}
};

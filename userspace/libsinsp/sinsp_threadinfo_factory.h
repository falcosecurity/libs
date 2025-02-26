#pragma once
#include <libsinsp/threadinfo.h>
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

#pragma once
#include <libsinsp/threadinfo.h>
#include <libsinsp/sinsp_external_processor.h>

/*!
  \brief Factory hiding sinsp_fdinfo creation details.
*/
class sinsp_fdinfo_factory {
	sinsp* m_sinsp;
	std::shared_ptr<sinsp_thread_manager> m_thread_manager;
	libsinsp::event_processor** m_external_event_processor;

	libsinsp::event_processor* get_external_event_processor() const {
		return *m_external_event_processor;
	}

public:
	sinsp_fdinfo_factory(sinsp* sinsp,
	                     const std::shared_ptr<sinsp_thread_manager>& thread_manager,
	                     libsinsp::event_processor** external_event_processor):
	        m_sinsp{sinsp},
	        m_thread_manager{thread_manager},
	        m_external_event_processor{external_event_processor} {}

	std::unique_ptr<sinsp_fdinfo> create() const {
		const auto external_event_processor = get_external_event_processor();
		auto ret = external_event_processor ? external_event_processor->build_fdinfo(m_sinsp)
		                                    : m_thread_manager->new_fdinfo();
		m_thread_manager->set_fdinfo_shared_dynamic_fields(*ret);
		return ret;
	}
};

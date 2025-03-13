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

public:
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
		                                       : std::make_unique<sinsp_fdinfo>();
		fdinfo->set_dynamic_fields(m_dyn_fields);
		return fdinfo;
	}
};

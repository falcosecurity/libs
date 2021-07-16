#pragma once

#include "container_engine/container_engine_base.h"
#include "container_engine/docker_base.h"

namespace libsinsp {
namespace container_engine {

class docker_win : public docker_base
{
public:
	docker_win(container_cache_interface &cache, const wmi_handle_source&);

	// implement container_engine_base
	bool resolve(sinsp_threadinfo *tinfo, bool query_os_for_missing_info) override;
	void update_with_size(const std::string& container_id) override;

private:
	static std::string s_incomplete_info_name;
	const wmi_handle_source& m_wmi_handle_source;
};

}
}

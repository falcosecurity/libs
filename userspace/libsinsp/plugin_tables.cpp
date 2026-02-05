#include <libsinsp/plugin_tables.h>
#include <libsinsp/sinsp.h>
#include <libsinsp/user.h>

void plugin_tables::init(const sinsp& inspector) {
	// Add "container_id" accessor.
	const auto& fields = inspector.m_thread_manager->dynamic_fields()->fields();
	if(const auto field = fields.find("container_id"); field != fields.end()) {
		m_container_id_field = field->second.new_accessor<std::string>();
	} else {
		throw sinsp_exception("failed to find dynamic field 'container_id' in threadinfo");
	}

	// Add "containers" table.
	auto containers_table = inspector.get_table_registry()->get_table<std::string>("containers");
	if(containers_table == nullptr) {
		throw sinsp_exception("failed to get containers table from threadinfo");
	}
	m_containers_table = std::make_unique<sinsp_table<std::string>>(this, containers_table);

	m_container_user_field = m_containers_table->get_field<std::string>("user");
	if(m_container_user_field == nullptr) {
		throw sinsp_exception("failed to get containers user field");
	}

	m_container_ip_field = m_containers_table->get_field<std::string>("ip");
	if(m_container_ip_field == nullptr) {
		throw sinsp_exception("failed to get containers ip field");
	}
}

std::string plugin_tables::get_container_id(sinsp_threadinfo& threadinfo) const {
	if(!m_container_id_field) {
		return {};
	}
	std::string container_id;
	threadinfo.read_field(*m_container_id_field, container_id);
	return container_id;
}

std::string plugin_tables::get_container_user(sinsp_threadinfo& threadinfo) const {
	std::string user;

	const auto container_id = get_container_id(threadinfo);
	if(!container_id.empty()) {
		try {
			auto e = m_containers_table->get_entry(container_id);
			e.read_field(m_container_user_field, user);
		} catch(...) {
			libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
			                          "Failed to read user from container %s",
			                          container_id.c_str());
		}
	}
	return user;
}

std::string plugin_tables::get_container_ip(sinsp_threadinfo& threadinfo) const {
	std::string ip;

	const auto container_id = get_container_id(threadinfo);
	if(container_id.empty()) {
		return ip;
	}
	try {
		auto e = m_containers_table->get_entry(container_id);
		e.read_field(m_container_ip_field, ip);
	} catch(...) {
		libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
		                          "Failed to read ip from container %s",
		                          container_id.c_str());
	}
	return ip;
}

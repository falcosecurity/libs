#include <libsinsp/plugin_tables.h>
#include <libsinsp/sinsp.h>
#include <libsinsp/user.h>

void plugin_tables::init(const sinsp& inspector) {
	// Add "container_id" accessor.
	auto container_id_field =
	        inspector.m_thread_manager->get_field("container_id",
	                                              libsinsp::state::typeinfo::of<std::string>());
	if(container_id_field == nullptr) {
		throw sinsp_exception("failed to find dynamic field 'container_id' in threadinfo");
	}

	auto container_id_field_ptr = dynamic_cast<libsinsp::state::typed_accessor<std::string>*>(
	        container_id_field.release());
	if(container_id_field_ptr == nullptr) {
		delete container_id_field_ptr;
		throw sinsp_exception("invalid type of field 'container_id' in threadinfo");
	}
	m_container_id_field =
	        std::unique_ptr<libsinsp::state::typed_accessor<std::string>>(container_id_field_ptr);

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
	return threadinfo.read_field(*m_container_id_field);
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

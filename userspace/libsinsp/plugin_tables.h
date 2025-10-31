#pragma once

#include <string>
#include <libsinsp/plugin.h>
#include <libsinsp/state/table.h>
#include <libsinsp/state/dynamic_struct.h>

class sinsp;
class sinsp_threadinfo;
class sinsp_usergroup_manager;
struct scap_userinfo;
struct scap_groupinfo;

/**
 * Access well-known tables and dynamic fields from plugins in sinsp core.
 *
 * Currently, supports the container plugin only.
 */
class plugin_tables : public libsinsp::state::sinsp_table_owner {
public:
	plugin_tables() = default;
	void init(const sinsp& inspector);

	/*!
	  \brief Return the container_id associated with this thread, if the container plugins is
	  running, leveraging sinsp state table API.
	*/
	std::string get_container_id(sinsp_threadinfo& threadinfo) const;

	/*!
	  \brief Given the container_id associated with this thread, fetches the container user from
	  the containers table, created by the container plugins if running, leveraging sinsp state
	  table API.
	*/
	std::string get_container_user(sinsp_threadinfo& threadinfo) const;

	/*!
	  \brief Given the container_id associated with this thread, feetches the container ip from the
	  containers table, created by the container plugins if running, leveraging sinsp state table
	  API.
	*/
	std::string get_container_ip(sinsp_threadinfo& threadinfo) const;

	template<typename F>
	bool foreach_container_ip(const F& func) {
		return m_containers_table->foreach_entry([&](sinsp_table_entry& e) -> bool {
			std::string ip;
			e.read_field(m_container_ip_field, ip);
			return func(ip);
		});
	}

private:
	std::unique_ptr<libsinsp::state::dynamic_struct::field_accessor<std::string>>
	        m_container_id_field;

	std::unique_ptr<sinsp_table<std::string>> m_containers_table;
	ss_plugin_table_field_t* m_container_user_field = nullptr;
	ss_plugin_table_field_t* m_container_ip_field = nullptr;
};

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

#define DEFAULT_EXPIRED_CHILDREN_THRESHOLD 10

#include <functional>
#include <memory>
#include <set>

#include <libscap/scap_savefile_api.h>
#include <libsinsp/fdtable.h>
#include <libsinsp/state/table.h>
#include <libsinsp/event.h>
#include <libsinsp/plugin.h>
#include <libsinsp/threadinfo.h>
#include <libsinsp/thread_group_info.h>
#include <libsinsp/sinsp_threadinfo_factory.h>
#include <libsinsp/timestamper.h>

class sinsp_observer;

///////////////////////////////////////////////////////////////////////////////
// This class manages the thread table
///////////////////////////////////////////////////////////////////////////////
class SINSP_PUBLIC sinsp_thread_manager : public libsinsp::state::built_in_table<int64_t>,
                                          public libsinsp::state::sinsp_table_owner {
public:
	sinsp_thread_manager(const sinsp_mode& sinsp_mode,
	                     const sinsp_threadinfo_factory& threadinfo_factory,
	                     sinsp_observer* const& observer,
	                     const std::shared_ptr<const sinsp_plugin>& input_plugin,
	                     const bool& large_envs_enabled,
	                     const timestamper& timestamper,
	                     const int64_t& sinsp_pid,
	                     const uint64_t& threads_purging_scan_time_ns,
	                     const uint64_t& thread_timeout_ns,
	                     const std::shared_ptr<sinsp_stats_v2>& sinsp_stats_v2,
	                     scap_platform* const& scap_platform,
	                     scap_t* const& scap_handle,
	                     const std::shared_ptr<libsinsp::state::dynamic_struct::field_infos>&
	                             thread_manager_dyn_fields,
	                     const std::shared_ptr<libsinsp::state::dynamic_struct::field_infos>&
	                             fdtable_dyn_fields);
	void clear();

	const threadinfo_map_t::ptr_t& add_thread(std::unique_ptr<sinsp_threadinfo> threadinfo,
	                                          bool from_scap_proctable);
	sinsp_threadinfo* find_new_reaper(sinsp_threadinfo*);
	void remove_thread(int64_t tid);
	// Returns true if the table is actually scanned
	// NOTE: this is implemented in sinsp.cpp so we can inline it from there
	inline bool remove_inactive_threads();
	void fix_sockets_coming_from_proc(bool resolve_hostname_and_port);

	typedef std::pair<std::string, libsinsp::state::dynamic_struct::field_accessor<std::string>>
	        foreign_field_accessor_entry;
	/*!
	  \brief Set the list of foreign field accessors. Any previously set foreign field accessor is
	    unset.
	  \param accessors A list of {field_name, field_accessor} pairs.
	 */
	void set_foreign_field_accessors(const std::vector<foreign_field_accessor_entry>& accessors) {
		m_foreign_fields_accessors = std::map{accessors.cbegin(), accessors.cend()};
	}

	typedef std::pair<std::string, base_table*> foreign_table_entry;
	/*!
	  \brief Set the list of foreign tables. Any previously set foreign table is unset.
	  \param tables A list of {table_name, table} pairs.
	 */
	void set_foreign_tables(const std::vector<foreign_table_entry>& tables) {
		m_foreign_tables.clear();
		for(const auto& [name, table] : tables) {
			m_foreign_tables.emplace(name, sinsp_table<std::string>(this, table));
		}
	}

	void reset_child_dependencies();
	void create_thread_dependencies_after_proc_scan();
	/*!
	  \brief Look up a thread given its tid and return its information,
	   and optionally go dig into proc if the thread is not in the thread table.

	  \param tid the ID of the thread. In case of multi-thread processes,
	   this corresponds to the PID.

	  \return the \ref sinsp_threadinfo object containing full thread information
	   and state.

	  \note if you are interested in a process' information, just give this
	  function with the PID of the process.

	  @throws a sinsp_exception containing the error string is thrown in case
	   of failure.
	*/
	const threadinfo_map_t::ptr_t& get_thread(int64_t tid,
	                                          bool lookup_only = true,
	                                          bool main_thread = false);

	//
	// Note: lookup_only should be used when the query for the thread is made
	//       not as a consequence of an event for that thread arriving, but
	//       just for lookup reason. In that case, m_lastaccess_ts is not updated
	//       and m_last_tinfo is not set.
	//
	const threadinfo_map_t::ptr_t& find_thread(int64_t tid, bool lookup_only);

	void dump_threads_to_file(scap_dumper_t* dumper);

	uint32_t get_thread_count() { return (uint32_t)m_threadtable.size(); }

	threadinfo_map_t* get_threads() { return &m_threadtable; }

	std::set<uint16_t> m_server_ports;

	void set_max_thread_table_size(uint32_t value);

	int32_t get_m_n_proc_lookups() const { return m_n_proc_lookups; }
	int32_t get_m_n_main_thread_lookups() const { return m_n_main_thread_lookups; }
	uint64_t get_m_n_proc_lookups_duration_ns() const { return m_n_proc_lookups_duration_ns; }
	void reset_thread_counters() {
		m_n_proc_lookups = 0;
		m_n_main_thread_lookups = 0;
		m_n_proc_lookups_duration_ns = 0;
	}

	void set_m_max_n_proc_lookups(int32_t val) { m_max_n_proc_lookups = val; }
	void set_m_max_n_proc_socket_lookups(int32_t val) { m_max_n_proc_socket_lookups = val; }
	/*!
	 * \brief Set time period for resetting process lookup counters
	 *
	 * Controls how frequently process lookup counters are reset, allowing
	 * the system to perform up to max_n_proc_lookups within each period.
	 * This prevents excessive OS queries while ensuring processes are still
	 * discovered over time.
	 *
	 * \param val Duration in milliseconds between counter resets (0 to disable)
	 *
	 * \see set_m_max_n_proc_lookups
	 */
	void set_proc_lookup_period_ms(uint64_t val) { m_proc_lookup_period = val * 1000000LL; }

	// ---- libsinsp::state::table implementation ----

	size_t entries_count() const override { return m_threadtable.size(); }

	void clear_entries() override { m_threadtable.clear(); }

	std::unique_ptr<libsinsp::state::table_entry> new_entry() const override;

	bool foreach_entry(std::function<bool(libsinsp::state::table_entry& e)> pred) override {
		return m_threadtable.loop([&pred](sinsp_threadinfo& e) { return pred(e); });
	}

	std::shared_ptr<libsinsp::state::table_entry> get_entry(const int64_t& key) override {
		return find_thread(key, true);
	}

	std::shared_ptr<libsinsp::state::table_entry> add_entry(
	        const int64_t& key,
	        std::unique_ptr<libsinsp::state::table_entry> entry) override {
		if(!entry) {
			throw sinsp_exception("null entry added to thread table");
		}
		auto tinfo = dynamic_cast<sinsp_threadinfo*>(entry.get());
		if(!tinfo) {
			throw sinsp_exception("unknown entry type added to thread table");
		}
		entry.release();
		tinfo->m_tid = key;
		return add_thread(std::unique_ptr<sinsp_threadinfo>(tinfo), false);
	}

	bool erase_entry(const int64_t& key) override {
		// todo(jasondellaluce): should we trigger the whole removal logic,
		// or should we just erase the table entry?
		// todo(jasondellaluce): should we make m_tid_to_remove a list, in case
		// we have more than one thread removed in a given event loop iteration?
		if(m_threadtable.get(key)) {
			this->remove_thread(key);
			return true;
		}
		return false;
	}

	const libsinsp::state::dynamic_struct::field_accessor<std::string>* get_field_accessor(
	        const std::string& field) const {
		if(m_foreign_fields_accessors.count(field) > 0) {
			return &m_foreign_fields_accessors.at(field);
		}
		return nullptr;
	}

	inline sinsp_table<std::string>* get_table(std::string table) {
		if(m_foreign_tables.count(table) > 0) {
			return &m_foreign_tables.at(table);
		}
		return nullptr;
	}

	const std::shared_ptr<thread_group_info>& get_thread_group_info(const int64_t pid) const {
		if(const auto tgroup = m_thread_groups.find(pid); tgroup != m_thread_groups.end()) {
			return tgroup->second;
		}
		return m_nullptr_tginfo_ret;
	}

	void set_thread_group_info(const int64_t pid,
	                           const std::shared_ptr<thread_group_info>& tginfo) {
		// It should be impossible to have a pid conflict. Right now we manage it by replacing the
		// old entry with the new one.
		if(const auto [it, inserted] = m_thread_groups.emplace(pid, tginfo); !inserted) {
			it->second = tginfo;
		}
	}

	void create_thread_dependencies(const std::shared_ptr<sinsp_threadinfo>& tinfo);

	void thread_to_scap(sinsp_threadinfo& tinfo, scap_threadinfo* sctinfo);

	void maybe_log_max_lookup(int64_t tid, bool scan_sockets, uint64_t period);

	inline uint64_t get_last_flush_time_ns() const { return m_last_flush_time_ns; }

	inline void set_last_flush_time_ns(uint64_t v) { m_last_flush_time_ns = v; }

	inline uint32_t get_max_thread_table_size() const { return m_max_thread_table_size; }

	// Tables and fields names.
	constexpr static auto s_containers_table_name = "containers";
	constexpr static auto s_containers_table_field_user = "user";
	constexpr static auto s_containers_table_field_ip = "ip";
	constexpr static auto s_container_id_field_name = "container_id";

	/*!
	  \brief Account the file descriptor for the provided thread.

	  \param tinfo The thread the provided fd must be accounted to.
	  \param fdinfo The file descriptor the provided thread must be accounted for.
	  \param resolve_hostname_and_port A flag indicating if, in case of socket file descriptors, the
	    hostname and port must be resolved.

	  \return the \ref sinsp_fdinfo object containing full file descriptor information.

	  \note tinfo must be a reference to a thread that is already present in the thread table.
	*/
	sinsp_fdinfo* add_thread_fd_from_scap(sinsp_threadinfo& tinfo,
	                                      const scap_fdinfo& fdinfo,
	                                      bool resolve_hostname_and_port);

private:
	inline void clear_thread_pointers(sinsp_threadinfo& threadinfo);
	void free_dump_fdinfos(std::vector<scap_fdinfo*>* fdinfos_to_free);
	void remove_main_thread_fdtable(sinsp_threadinfo* main_thread) const;

	bool is_syscall_plugin_enabled() const {
		return m_sinsp_mode.is_plugin() && m_input_plugin->id() == 0;
	}

	bool is_large_envs_enabled() const {
		return (m_sinsp_mode.is_live() || is_syscall_plugin_enabled()) && m_large_envs_enabled;
	}

	bool must_notify_thread_user_update() const {
		return m_sinsp_mode.is_live() || is_syscall_plugin_enabled();
	}

	bool must_notify_thread_group_update() const {
		return m_sinsp_mode.is_live() || is_syscall_plugin_enabled();
	}

	// The following fields are externally provided and access to them is expected to be read-only.
	const sinsp_mode& m_sinsp_mode;
	const sinsp_threadinfo_factory& m_threadinfo_factory;
	sinsp_observer* const& m_observer;
	const std::shared_ptr<const sinsp_plugin>& m_input_plugin;
	const bool& m_large_envs_enabled;
	const timestamper& m_timestamper;
	const int64_t& m_sinsp_pid;
	const uint64_t& m_threads_purging_scan_time_ns;
	const uint64_t& m_thread_timeout_ns;

	// The following fields are externally provided and expected to be populated/updated by the
	// thread manager.
	std::shared_ptr<sinsp_stats_v2> m_sinsp_stats_v2;
	scap_platform* const& m_scap_platform;
	scap_t* const& m_scap_handle;
	const std::shared_ptr<libsinsp::state::dynamic_struct::field_infos> m_fdtable_dyn_fields;

	/* the key is the pid of the group, and the value is a shared pointer to the thread_group_info
	 */
	std::unordered_map<int64_t, std::shared_ptr<thread_group_info>> m_thread_groups;
	threadinfo_map_t m_threadtable;
	int64_t m_last_tid;
	std::shared_ptr<sinsp_threadinfo> m_last_tinfo;
	uint64_t m_last_flush_time_ns;
	// Increased legacy default of 131072 in January 2024 to prevent
	// possible drops due to full threadtable on more modern servers
	const uint32_t m_thread_table_default_size = 262144;
	uint32_t m_max_thread_table_size;
	int32_t m_n_proc_lookups = 0;
	uint64_t m_n_proc_lookups_duration_ns = 0;
	int32_t m_n_main_thread_lookups = 0;
	int32_t m_max_n_proc_lookups = -1;
	int32_t m_max_n_proc_socket_lookups = -1;
	uint64_t m_proc_lookup_period = 0;
	uint64_t m_last_proc_lookup_period_start = 0;

	const std::shared_ptr<sinsp_threadinfo>
	        m_nullptr_tinfo_ret;  // needed for returning a reference
	const std::shared_ptr<thread_group_info>
	        m_nullptr_tginfo_ret;  // needed for returning a reference

	// State table API field accessors to foreign keys written by plugins.
	std::map<std::string, libsinsp::state::dynamic_struct::field_accessor<std::string>>
	        m_foreign_fields_accessors;
	// State tables exposed by plugins
	std::map<std::string, sinsp_table<std::string>> m_foreign_tables;

	// Tables and fields names.
	constexpr static auto s_thread_table_name = "threads";
};

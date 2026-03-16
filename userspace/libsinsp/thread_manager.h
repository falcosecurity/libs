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

#include <array>
#include <atomic>
#include <functional>
#include <memory>
#include <set>
#include <shared_mutex>

#include <libscap/scap_savefile_api.h>
#include <libsinsp/fdtable.h>
#include <libsinsp/state/table.h>
#include <libsinsp/event.h>
#include <libsinsp/plugin.h>
#include <libsinsp/threadinfo_map.h>
#include <libsinsp/thread_group_info.h>
#include <libsinsp/sinsp_threadinfo_factory.h>
#include <libsinsp/timestamper.h>

class sinsp_observer;

///////////////////////////////////////////////////////////////////////////////
// Manages the thread table. Add/remove/lookup/iteration are thread-safe when
// built with LIBSINSP_USE_FOLLY (Folly ConcurrentHashMap).
///////////////////////////////////////////////////////////////////////////////
class SINSP_PUBLIC sinsp_thread_manager : public libsinsp::state::extensible_table<int64_t>,
                                          public libsinsp::state::sinsp_table_owner {
public:
	sinsp_thread_manager(
	        const sinsp_threadinfo_factory& threadinfo_factory,
	        sinsp_observer* const& observer,
	        const timestamper& timestamper,
	        const int64_t& sinsp_pid,
	        const uint64_t& threads_purging_scan_time_ns,
	        const uint64_t& thread_timeout_ns,
	        const std::shared_ptr<sinsp_stats_v2>& sinsp_stats_v2,
	        scap_platform* const& scap_platform,
	        scap_t* const& scap_handle,
	        const std::shared_ptr<libsinsp::state::dynamic_field_infos>& thread_manager_dyn_fields,
	        const std::shared_ptr<libsinsp::state::dynamic_field_infos>& fdtable_dyn_fields);
	void clear();

	/*!
	  \brief Add a thread to the table.
	  \return shared_ptr to the inserted (or existing) thread, or empty if table full. Safe for
	  concurrent use.
	*/
	threadinfo_map_t::ptr_t add_thread(std::unique_ptr<sinsp_threadinfo> threadinfo,
	                                   bool must_create_thread_dependencies);

	/*!
	  \brief Find the new reaper for a thread being removed (e.g. for reparenting children).
	  \param tinfo the thread that is being removed (must not be null).
	  \return shared_ptr to the reaper thread, or empty if none (e.g. loop detected).
	  Caller holds a reference; safe for concurrent use.
	*/
	threadinfo_map_t::ptr_t find_new_reaper(sinsp_threadinfo* tinfo);
	void remove_thread(int64_t tid);

	/*!
	  \brief Record a TID that was removed due to a procexit event.
	  This is used to prevent the caller's clone exit handler from
	  re-adding a child that has already exited.

	  \param tid the thread ID being removed.
	  \param ptid the parent thread ID of the removed thread.
	  \param ts the event timestamp of the removal.
	*/
	void record_recently_exited(int64_t tid, int64_t ptid, uint64_t ts);

	/*!
	  \brief Check if a TID was recently removed due to a procexit event.
	  Uses a composite (ptid, tid) key to avoid false positives from TID
	  recycling. Only matches entries recorded within the last 2 seconds.

	  \param tid the thread ID to check.
	  \param ptid the expected parent thread ID of the child.
	  \param ts the current event timestamp.
	*/
	bool has_recently_exited(int64_t tid, int64_t ptid, uint64_t ts) const;

	// Returns true if the table is actually scanned
	// NOTE: this is implemented in sinsp.cpp so we can inline it from there
	inline bool remove_inactive_threads();
	void fix_sockets_coming_from_proc(bool resolve_hostname_and_port);

	void reset_child_dependencies();
	void create_thread_dependencies_after_proc_scan();
	/*!
	  \brief Look up a thread given its tid and return its information,
	   and optionally go dig into proc if the thread is not in the thread table.

	  \param tid the ID of the thread. In case of multi-thread processes,
	   this corresponds to the PID.

	  \return a copy of the shared_ptr to the thread info, or empty if not found.
	   Caller holds a reference; safe for concurrent use (no internal cache).

	  \note if you are interested in a process' information, just give this
	  function with the PID of the process.

	  @throws a sinsp_exception containing the error string is thrown in case
	   of failure.
	*/
	threadinfo_map_t::ptr_t get_thread(int64_t tid,
	                                   bool lookup_only = true,
	                                   bool main_thread = false);

	/*!
	  \brief Look up a thread by TID; if not found, add a minimal in-memory entry
	  without querying the OS. For use when the event source (e.g. plugin) does not
	  have a real process table.
	  \return shared_ptr to the thread info. Safe for concurrent use.
	*/
	threadinfo_map_t::ptr_t get_or_create_fake_thread(int64_t tid);

	/*!
	  \brief Look up a thread by TID without creating it from /proc.
	  \param lookup_only when false, updates the thread's m_lastaccess_ts and main fdtable; use true
	  for read-only lookups. \return shared_ptr to the thread info, or empty if not found.
	*/
	threadinfo_map_t::ptr_t find_thread(int64_t tid, bool lookup_only);

	/*!
	  \brief Get the process that launched this thread's process (its parent) or any of its
	  ancestors.
	  \param tinfo the thread whose ancestor to look up.
	  \param n when 1 look for the parent process, when 2 the grandparent, and so forth.
	  \return shared_ptr to the ancestor threadinfo, or empty if it does not exist or was removed.
	  Caller holds a reference; safe for concurrent use.
	*/
	threadinfo_map_t::ptr_t get_ancestor_process(sinsp_threadinfo& tinfo, uint32_t n = 1);
	/*!
	  \brief Walk up the parent process hierarchy, calling the provided function for each node.
	  If the function returns false, the traversal stops.
	  \note tinfo and the visitor must remain valid for the duration; use a shared_ptr or
	  callback scope where the table holds a reference.
	*/
	typedef std::function<bool(sinsp_threadinfo*)> visitor_func_t;
	void traverse_parent_state(sinsp_threadinfo& tinfo, visitor_func_t& visitor);

	/*!
	  \brief Return the oldest ancestor for which get_thread_id matches the given id (e.g. session
	  leader). \param tinfo the thread to start from. \param get_thread_id function returning the id
	  to match (e.g. sid, pgid). \param is_virtual_id if true, resolve in pid-namespace context.
	  \return shared_ptr to the matching ancestor, or empty if none. Caller holds a reference.
	*/
	threadinfo_map_t::ptr_t get_oldest_matching_ancestor(
	        sinsp_threadinfo* tinfo,
	        const std::function<int64_t(sinsp_threadinfo*)>& get_thread_id,
	        bool is_virtual_id = false);

	/*! \brief Return a string field from the oldest matching ancestor (e.g. session leader). Uses
	 * get_oldest_matching_ancestor internally. */
	std::string get_ancestor_field_as_string(
	        sinsp_threadinfo* tinfo,
	        const std::function<int64_t(sinsp_threadinfo*)>& get_thread_id,
	        const std::function<std::string(sinsp_threadinfo*)>& get_field_str,
	        bool is_virtual_id = false);

	void dump_threads_to_file(scap_dumper_t* dumper);

	/*! \return Approximate number of threads in the table (rolling count when using concurrent
	 * storage). */
	uint32_t get_thread_count() { return (uint32_t)m_threadtable.size(); }

	/*! \brief Iterate over all threads, calling \a callback with a const reference to each.
	 * Return false from the callback to stop iteration. Safe for concurrent use.
	 * Template avoids std::function allocation; callback signature: bool(const sinsp_threadinfo&).
	 */
	template<typename Visitor>
	bool loop_threads(Visitor&& callback) const {
		return m_threadtable.const_loop_shared_pointer(
		        [&callback](const std::shared_ptr<sinsp_threadinfo>& ptr) {
			        if(!ptr) {
				        return true;
			        }
			        return callback(*ptr);
		        });
	}

	std::set<uint16_t> m_server_ports;
	mutable std::shared_mutex m_server_ports_mutex; /* protects m_server_ports */

	void set_max_thread_table_size(uint32_t value);

	int32_t get_m_n_proc_lookups() const { return m_n_proc_lookups.load(); }
	int32_t get_m_n_main_thread_lookups() const { return m_n_main_thread_lookups.load(); }
	uint64_t get_m_n_proc_lookups_duration_ns() const {
		return m_n_proc_lookups_duration_ns.load();
	}
	void reset_thread_counters() {
		m_n_proc_lookups.store(0);
		m_n_main_thread_lookups.store(0);
		m_n_proc_lookups_duration_ns.store(0);
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

	bool foreach_entry(std::function<bool(libsinsp::state::table_entry& e)> pred) override;

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
		return add_thread(std::unique_ptr<sinsp_threadinfo>(tinfo), true);
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

	const libsinsp::state::dynamic_field_accessor<std::string>* get_field_accessor(
	        const std::string& field) const {
		if(auto it = m_foreign_fields_accessors.find(field);
		   it != m_foreign_fields_accessors.end()) {
			return &it->second;
		}
		return nullptr;
	}

	inline sinsp_table<std::string>* get_table(const std::string& table) {
		if(m_foreign_tables.count(table) > 0) {
			return &m_foreign_tables.at(table);
		}
		return nullptr;
	}

	/** Returns a copy of the shared_ptr so callers hold a reference; thread-safe. */
	std::shared_ptr<thread_group_info> get_thread_group_info(const int64_t pid) const;

	void set_thread_group_info(const int64_t pid, const std::shared_ptr<thread_group_info>& tginfo);

	void create_thread_dependencies(const std::shared_ptr<sinsp_threadinfo>& tinfo);

	void thread_to_scap(sinsp_threadinfo& tinfo, scap_threadinfo* sctinfo);

	void maybe_log_max_lookup(int64_t tid, bool scan_sockets, uint64_t period);

	inline uint64_t get_last_flush_time_ns() const { return m_last_flush_time_ns.load(); }

	inline void set_last_flush_time_ns(uint64_t v) { m_last_flush_time_ns.store(v); }

	inline uint32_t get_max_thread_table_size() const { return m_max_thread_table_size; }

	/*!
	  \brief Account the file descriptor for the provided thread.

	  \param tinfo The thread the provided fd must be accounted to.
	  \param fdinfo The file descriptor the provided thread must be accounted for.
	  \param resolve_hostname_and_port A flag indicating if, in case of socket file descriptors, the
	    hostname and port must be resolved.

	  \return the \ref sinsp_fdinfo object containing full file descriptor information.

	  \note tinfo must be a reference to a thread that is already present in the thread table.
	*/
	std::shared_ptr<sinsp_fdinfo> add_thread_fd_from_scap(sinsp_threadinfo& tinfo,
	                                                      const scap_fdinfo& fdinfo,
	                                                      bool resolve_hostname_and_port);

private:
	/* We call it immediately before removing the thread from the thread table. */
	void remove_child_from_parent(int64_t ptid, const std::shared_ptr<sinsp_threadinfo>& child);

	inline void clear_thread_pointers(sinsp_threadinfo& threadinfo);
	void free_dump_fdinfos(std::vector<scap_fdinfo*>* fdinfos_to_free);
	void remove_main_thread_fdtable(sinsp_threadinfo* main_thread) const;

	// The following fields are externally provided and access to them is expected to be read-only.
	const sinsp_threadinfo_factory& m_threadinfo_factory;
	sinsp_observer* const& m_observer;
	const timestamper& m_timestamper;
	const int64_t& m_sinsp_pid;
	const uint64_t& m_threads_purging_scan_time_ns;
	const uint64_t& m_thread_timeout_ns;

	// The following fields are externally provided and expected to be populated/updated by the
	// thread manager.
	std::shared_ptr<sinsp_stats_v2> m_sinsp_stats_v2;
	scap_platform* const& m_scap_platform;
	scap_t* const& m_scap_handle;
	std::mutex m_scap_proc_mutex;
	const std::shared_ptr<libsinsp::state::dynamic_field_infos> m_fdtable_dyn_fields;

	/* the key is the pid of the group, and the value is a shared pointer to the thread_group_info.
	 * Protected by m_thread_groups_mutex for thread-safe access.
	 */
	std::unordered_map<int64_t, std::shared_ptr<thread_group_info>> m_thread_groups;
	mutable std::shared_mutex m_thread_groups_mutex;
	threadinfo_map_t m_threadtable;
	std::atomic<uint64_t> m_last_flush_time_ns{0};
	// Increased legacy default of 131072 in January 2024 to prevent
	// possible drops due to full threadtable on more modern servers
	const uint32_t m_thread_table_default_size = 262144;
	uint32_t m_max_thread_table_size;
	std::atomic<int32_t> m_n_proc_lookups{0};
	std::atomic<uint64_t> m_n_proc_lookups_duration_ns{0};
	std::atomic<int32_t> m_n_main_thread_lookups{0};
	int32_t m_max_n_proc_lookups = -1;
	int32_t m_max_n_proc_socket_lookups = -1;
	uint64_t m_proc_lookup_period = 0;
	std::atomic<uint64_t> m_last_proc_lookup_period_start{0};

	// State table API: field accessors and tables for plugin-provided (foreign) state.
	// Populated only during single-threaded init (plugin load / inspector init) and
	// read-only thereafter during concurrent use. No mutex required for reads.
	std::map<std::string, libsinsp::state::dynamic_field_accessor<std::string>>
	        m_foreign_fields_accessors;
	std::map<std::string, sinsp_table<std::string>> m_foreign_tables;

	// Ring buffer of recently-exited TIDs (from procexit events).
	// Used to prevent the caller's clone exit handler from re-adding
	// children that have already exited. Each entry stores a composite
	// key of (ptid, tid) packed into a uint64_t (upper 32 bits = ptid,
	// lower 32 bits = tid) alongside a timestamp for stale-entry
	// detection. The composite key avoids false positives from TID
	// recycling — both parent and child TIDs would need to be recycled
	// simultaneously for a collision to occur.
	struct recently_exited_entry {
		uint64_t key = 0;  // ((uint32_t)ptid << 32) | (uint32_t)tid
		uint64_t ts = 0;
	};
	static constexpr size_t RECENTLY_EXITED_RING_SIZE = 8192;
	std::array<recently_exited_entry, RECENTLY_EXITED_RING_SIZE> m_recently_exited_tids{};
	size_t m_recently_exited_write_idx = 0;
	mutable std::shared_mutex m_recently_exited_mutex;

	// Tables and fields names.
	constexpr static auto s_thread_table_name = "threads";
};

// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

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

#ifndef VISIBILITY_PRIVATE
#define VISIBILITY_PRIVATE private:
#endif

#ifdef _WIN32
struct iovec {
	void  *iov_base;    /* Starting address */
	size_t iov_len;     /* Number of bytes to transfer */
};
#else
#include <sys/uio.h>
#endif

#include <functional>
#include <memory>
#include <set>
#include <libsinsp/fdinfo.h>
#include <libsinsp/state/table.h>
#include <libsinsp/thread_group_info.h>

class sinsp_delays_info;
class blprogram;

struct erase_fd_params
{
	bool m_remove_from_table;
	int64_t m_fd;
	sinsp_threadinfo* m_tinfo;
	sinsp_fdinfo* m_fdinfo;
	uint64_t m_ts;
};

/** @defgroup state State management
 *  @{
 */

/*!
  \brief Thread/process information class.
  This class contains the full state for a thread, and a bunch of functions to
  manipulate threads and retrieve thread information.

  \note As a library user, you won't need to construct thread objects. Rather,
   you get them by calling \ref sinsp_evt::get_thread_info or
   \ref sinsp::get_thread.
  \note sinsp_threadinfo is also used to keep process state. For the sinsp
   library, a process is just a thread with TID=PID.
*/
class SINSP_PUBLIC sinsp_threadinfo : public libsinsp::state::table_entry
{
public:
	sinsp_threadinfo(
		sinsp *inspector = nullptr,
		std::shared_ptr<libsinsp::state::dynamic_struct::field_infos> dyn_fields = nullptr);
	virtual ~sinsp_threadinfo();

	/*!
	  \brief Return the name of the process containing this thread, e.g. "top".
	*/
	std::string get_comm() const;

	/*!
	  \brief Return the name of the process containing this thread from argv[0], e.g. "/bin/top".
	*/
	std::string get_exe() const;

	/*!
	  \brief Return the full executable path of the process containing this thread, e.g. "/bin/top".
	*/
	std::string get_exepath() const;

	/*!
	  \brief Return the working directory of the process containing this thread.
	*/
	std::string get_cwd();

	/*!
	  \brief Return the values of all environment variables for the process
	  containing this thread.
	*/
	const std::vector<std::string>& get_env();

	/*!
	  \brief Return the value of the specified environment variable for the process
	  containing this thread. Returns empty string if variable is not found.
	*/
	std::string get_env(const std::string& name);

	/*!
	  \brief Return concatenated environment variables with the format of "ENV_NAME=value ENV_NAME1=value1" ...
	*/
	std::string concatenate_all_env();

	/*!
	  \brief Return true if this is a process' main thread.
	*/
	inline bool is_main_thread() const
	{
		return (m_tid == m_pid) || m_flags & PPM_CL_IS_MAIN_THREAD;
	}

	/*!
	  \brief Return true if this thread belongs to a pid namespace.
	*/
	inline bool is_in_pid_namespace() const
	{
		return (m_flags & PPM_CL_CHILD_IN_PIDNS || m_tid != m_vtid);
	}

	/*!
	  \brief Return true if the thread is invalid. Sometimes we create some
	  invalid thread info, if we are not able to scan proc.
	*/
	inline bool is_invalid() const
	{
		return m_tid < 0 || m_pid < 0 || m_ptid < 0;
	}

	/*!
	  \brief Return true if the thread is dead.
	*/
	inline bool is_dead() const
	{
		return m_flags & PPM_CL_CLOSED;
	}

	/*!
	  \brief Mark thread as dead.
	*/
	inline void set_dead()
	{
		m_flags |= PPM_CL_CLOSED;
	}

	/*!
	  \brief In some corner cases is possible that a dead main thread could
	  become again alive. For example, when an execve is performed by a secondary
	  thread and the main thread is already dead
	*/
	inline void resurrect_thread()
	{
		/* If the thread is not dead we do nothing.
		 * It should never happen
		 */
		if(!is_dead())
		{
			return;
		}

		m_flags &= ~PPM_CL_CLOSED;
		if(!m_tginfo)
		{
			return;
		}
		/* we increment again the threadcount since we
		 * decremented it during the proc_exit event.
		 */
		m_tginfo->increment_thread_count();
	}

	/*!
		\brief Return the number of alive threads in the thread group, including the thread leader.
	*/
	inline uint64_t get_num_threads() const
	{
		return m_tginfo ? m_tginfo->get_thread_count() : 0;
	}

	/*!
		\brief Return the number of alive threads in the thread group, excluding the thread leader.
	*/
	inline uint64_t get_num_not_leader_threads() const
	{
		if(!m_tginfo)
		{
			return 0;
		}

		auto main_thread = get_main_thread();
		if(main_thread != nullptr && !main_thread->is_dead())
		{
			return m_tginfo->get_thread_count()-1;
		}
		/* we don't have the main thread in the group or it is dead */
		return m_tginfo->get_thread_count();
	}

	/*
	  \brief returns true if there is a loop detected in the thread parent state.
	  Needs traverse_parent_state() to have been called first.
	*/
	inline bool parent_loop_detected() const
	{
		return m_parent_loop_detected;
	}

	/*!
	  \brief Get the main thread of the process containing this thread.
	*/
	inline sinsp_threadinfo* get_main_thread()
	{
		if(is_main_thread())
		{
			return this;
		}

		// This is possible when we have invalid threads
		if(m_tginfo == nullptr)
		{
			return nullptr;
		}

		// If we have the main thread in the group, it is always the first one
		auto possible_main = m_tginfo->get_first_thread();
		if(possible_main == nullptr || !possible_main->is_main_thread())
		{
			return nullptr;
		}
		return possible_main;
	}

	inline const sinsp_threadinfo* get_main_thread() const
	{
		return const_cast<sinsp_threadinfo*>(this)->get_main_thread();
	}

	/*!
	  \brief Get the process that launched this thread's process.
	*/
	sinsp_threadinfo* get_parent_thread();

	/*!
	  \brief Retrieve information about one of this thread/process FDs.

	  \param fd The file descriptor number, e.g. 0 for stdin.

	  \return Pointer to the FD information, or NULL if the given FD doesn't
	   exist
	*/
	inline sinsp_fdinfo* get_fd(int64_t fd)
	{
		if(fd < 0)
		{
			return NULL;
		}

		sinsp_fdtable* fdt = get_fd_table();

		if(fdt)
		{
			sinsp_fdinfo *fdinfo = fdt->find(fd);
			if(fdinfo)
			{
				// Its current name is now its old
				// name. The name might change as a
				// result of parsing.
				fdinfo->m_oldname = fdinfo->m_name;
				return fdinfo;
			}
		}

		return NULL;
	}

	/*!
	  \brief Iterate over open file descriptors in the process.

	  \return True if all callback invoations returned true, false if not
	*/
	bool loop_fds(sinsp_fdtable::fdtable_const_visitor_t visitor);

	/*!
	  \brief Return true if this thread is bound to the given server port.
	*/
	bool is_bound_to_port(uint16_t number) const;

	/*!
	  \brief Return true if this thread has a client socket open on the given port.
	*/
	bool uses_client_port(uint16_t number) const;

	/*!
	  \brief Return the ratio between open FDs and maximum available FDs for this thread.
	*/
	uint64_t get_fd_usage_pct();
	double get_fd_usage_pct_d();

	/*!
	  \brief Return the number of open FDs for this thread.
	*/
	uint64_t get_fd_opencount() const;

	/*!
	  \brief Return the maximum number of FDs this thread can open.
	*/
	uint64_t get_fd_limit();

	/*!
	  \brief Return the cgroup name for a specific subsystem

	  If the subsystem isn't mounted, return "/"
	 */
	const std::string& get_cgroup(const std::string& subsys) const;

	/*!
	  \brief Return the cgroup name for a specific subsystem

	  If the subsystem isn't mounted, return false and leave `cgroup`
	  unchanged
	 */
	bool get_cgroup(const std::string& subsys, std::string& cgroup) const;

	//
	// Walk up the parent process hierarchy, calling the provided
	// function for each node. If the function returns false, the
	// traversal stops.
	//
	typedef std::function<bool (sinsp_threadinfo *)> visitor_func_t;
	void traverse_parent_state(visitor_func_t &visitor);

	void assign_children_to_reaper(sinsp_threadinfo* reaper);

	inline void add_child(const std::shared_ptr<sinsp_threadinfo>& child)
	{
		m_children.push_front(child);
		/* Set current thread as parent */
		child->m_ptid = m_tid;
		/* Increment the number of not expired children */
		m_not_expired_children++;
	}

	/* We call it immediately before removing the thread from the thread table. */
	inline void remove_child_from_parent()
	{
		auto parent = get_parent_thread();
		if(parent == nullptr)
		{
			return;
		}

		parent->m_not_expired_children--;

		/* Clean expired children if necessary. */
		if((parent->m_children.size() - parent->m_not_expired_children) >= DEFAULT_EXPIRED_CHILDREN_THRESHOLD)
		{
			parent->clean_expired_children();
		}
	}

	inline void clean_expired_children()
	{
		auto child = m_children.begin();
		while(child != m_children.end())
		{
			/* This child is expired */
			if(child->expired())
			{
				/* `erase` returns the pointer to the next child
				 * no need for manual increment.
				 */
				child = m_children.erase(child);
				continue;
			}
			child++;
		}
	}

	static void populate_cmdline(std::string &cmdline, const sinsp_threadinfo *tinfo);

	// Return true if this thread is a part of a healthcheck,
	// readiness probe, or liveness probe.
	bool is_health_probe() const;

	/*!
	  \brief Translate a directory's file descriptor into its path
	  \param dir_fd  A file descriptor for a directory
	  \return  A path (or "" if failure)
	 */
	std::string get_path_for_dir_fd(int64_t dir_fd);

	void set_user(uint32_t uid);
	void set_group(uint32_t gid);
	void set_loginuser(uint32_t loginuid);

	using cgroups_t = std::vector<std::pair<std::string, std::string>>;
	cgroups_t& cgroups() const;

	//
	// Core state
	//
	int64_t m_tid;  ///< The id of this thread
	int64_t m_pid; ///< The id of the process containing this thread. In single thread threads, this is equal to tid.
	int64_t m_ptid; ///< The id of the process that started this thread.
	int64_t m_reaper_tid; ///< The id of the reaper for this thread
	int64_t m_sid; ///< The session id of the process containing this thread.
	std::string m_comm; ///< Command name (e.g. "top")
	std::string m_exe; ///< argv[0] (e.g. "sshd: user@pts/4")
	std::string m_exepath; ///< full executable path
	bool m_exe_writable;
	bool m_exe_upper_layer; ///< True if the executable file belongs to upper layer in overlayfs
	bool m_exe_from_memfd;	///< True if the executable is stored in fileless memory referenced by memfd
	std::vector<std::string> m_args; ///< Command line arguments (e.g. "-d1")
	std::vector<std::string> m_env; ///< Environment variables
	std::unique_ptr<cgroups_t> m_cgroups; ///< subsystem-cgroup pairs
	std::string m_container_id; ///< heuristic-based container id
	uint32_t m_flags; ///< The thread flags. See the PPM_CL_* declarations in ppm_events_public.h.
	int64_t m_fdlimit;  ///< The maximum number of FDs this thread can open
	scap_userinfo m_user; ///< user infos
	scap_userinfo m_loginuser; ///< loginuser infos (auid)
	scap_groupinfo m_group; ///< group infos
	uint64_t m_cap_permitted; ///< permitted capabilities
	uint64_t m_cap_effective; ///< effective capabilities
	uint64_t m_cap_inheritable; ///< inheritable capabilities
	uint64_t m_exe_ino; ///< executable inode ino
	uint64_t m_exe_ino_ctime; ///< executable inode ctime (last status change time)
	uint64_t m_exe_ino_mtime; ///< executable inode mtime (last modification time)
	uint64_t m_exe_ino_ctime_duration_clone_ts; ///< duration in ns between executable inode ctime (last status change time) and clone_ts
	uint64_t m_exe_ino_ctime_duration_pidns_start; ///< duration in ns between pidns start ts and executable inode ctime (last status change time) if pidns start predates ctime
	uint32_t m_vmsize_kb; ///< total virtual memory (as kb).
	uint32_t m_vmrss_kb; ///< resident non-swapped memory (as kb).
	uint32_t m_vmswap_kb; ///< swapped memory (as kb).
	uint64_t m_pfmajor; ///< number of major page faults since start.
	uint64_t m_pfminor; ///< number of minor page faults since start.
	int64_t m_vtid;  ///< The virtual id of this thread.
	int64_t m_vpid; ///< The virtual id of the process containing this thread. In single thread threads, this is equal to vtid.
	int64_t m_vpgid; // The virtual process group id, as seen from its pid namespace
	uint64_t m_pidns_init_start_ts; ///<The pid_namespace init task (child_reaper) start_time ts.
	std::string m_root;
	size_t m_program_hash; ///< Unique hash of the current program
	size_t m_program_hash_scripts;  ///< Unique hash of the current program, including arguments for scripting programs (like python or ruby)
	uint32_t m_tty; ///< Number of controlling terminal
	std::shared_ptr<thread_group_info> m_tginfo;
	std::list<std::weak_ptr<sinsp_threadinfo>> m_children;
	uint64_t m_not_expired_children;
	bool m_filtered_out; ///< True if this thread is filtered out by the inspector filter from saving to a capture

	// In some cases, a threadinfo has a category that identifies
	// why it was run. Descriptions:
	// CAT_NONE: no specific category
	// CAT_CONTAINER: a process run in a container and *not* any
	//                of the following more specific categories.
	// CAT_HEALTHCHECK: part of a container healthcheck
	// CAT_LIVENESS_PROBE: part of a k8s liveness probe
	// CAT_READINESS_PROBE: part of a k8s readiness probe
	enum command_category {
		CAT_NONE = 0,
		CAT_CONTAINER,
		CAT_HEALTHCHECK,
		CAT_LIVENESS_PROBE,
		CAT_READINESS_PROBE
	};

	command_category m_category;

	//
	// State for multi-event processing
	//
	int64_t m_lastevent_fd; ///< The FD os the last event used by this thread.
	uint64_t m_lastevent_ts; ///< timestamp of the last event for this thread.
	uint64_t m_prevevent_ts; ///< timestamp of the event before the last for this thread.
	uint64_t m_lastaccess_ts; ///< The last time this thread was looked up. Used when cleaning up the table.
	uint64_t m_clone_ts; ///< When the clone that started this process happened.
	uint64_t m_lastexec_ts; ///< The last time exec was called

	size_t args_len() const;
	size_t env_len() const;

	void args_to_iovec(struct iovec **iov, int *iovcnt,
			   std::string &rem) const;

	void env_to_iovec(struct iovec **iov, int *iovcnt,
			  std::string &rem) const;

	void cgroups_to_iovec(struct iovec **iov, int *iovcnt,
			      std::string &rem, const cgroups_t& cgroups) const;

	//
	// State for filtering
	//
	uint64_t m_last_latency_entertime;
	uint64_t m_latency;

	//
	// Global state
	//
	sinsp *m_inspector;

public: // types required for use in sets
	struct hasher {
		size_t operator()(sinsp_threadinfo* tinfo) const
		{
			auto main_thread = tinfo->get_main_thread();
			if(main_thread == nullptr)
			{
				return 0;
			}
			return main_thread->m_program_hash;
		}
	};

	struct comparer {
		size_t operator()(sinsp_threadinfo* lhs, sinsp_threadinfo* rhs) const
		{
			auto lhs_main_thread = lhs->get_main_thread();
			auto rhs_main_thread = rhs->get_main_thread();
			if(lhs_main_thread == nullptr || rhs_main_thread == nullptr)
			{
				return 0;
			}
			return lhs_main_thread->m_program_hash == rhs_main_thread->m_program_hash;
		}
	};

	/* Note that `fd_table` should be shared with the main thread only if `PPM_CL_CLONE_FILES`
	 * is specified. Today we always specify `PPM_CL_CLONE_FILES` for all threads.
	 */
	inline sinsp_fdtable* get_fd_table()
	{
		if(!(m_flags & PPM_CL_CLONE_FILES))
		{
			return &m_fdtable;
		}
		else
		{
			sinsp_threadinfo* root = get_main_thread();
			return (root == nullptr) ? nullptr : &(root->m_fdtable);
		}
	}

	inline const sinsp_fdtable* get_fd_table() const
	{
		return const_cast<sinsp_threadinfo*>(this)->get_fd_table();
	}

public:
VISIBILITY_PRIVATE
	void init();
	// return true if, based on the current inspector filter, this thread should be kept
	void init(scap_threadinfo* pi);
	void fix_sockets_coming_from_proc();
	sinsp_fdinfo* add_fd(int64_t fd, std::unique_ptr<sinsp_fdinfo> fdinfo);
	void add_fd_from_scap(scap_fdinfo *fdinfo);
	void remove_fd(int64_t fd);
	void set_cwd(std::string_view cwd);
	sinsp_threadinfo* get_cwd_root();
	void set_args(const char* args, size_t len);
	void set_env(const char* env, size_t len);
	bool set_env_from_proc();
	void set_cgroups(const char* cgroups, size_t len);
	bool is_lastevent_data_valid() const;
	inline void set_lastevent_data_validity(bool isvalid)
	{
		if(isvalid)
		{
			m_lastevent_cpuid = (uint16_t)1;
		}
		else
		{
			m_lastevent_cpuid = (uint16_t) - 1;
		}
	}
	void compute_program_hash();

	size_t strvec_len(const std::vector<std::string> &strs) const;
	void strvec_to_iovec(const std::vector<std::string> &strs,
			     struct iovec **iov, int *iovcnt,
			     std::string &rem) const;

	void add_to_iovec(const std::string &str,
			  const bool include_trailing_null,
			  struct iovec &iov,
			  uint32_t &alen,
			  std::string &rem) const;

	//  void push_fdop(sinsp_fdop* op);
	// the queue of recent fd operations
	//  std::deque<sinsp_fdop> m_last_fdop;

	//
	// Parameters that can't be accessed directly because they could be in the
	// parent thread info
	//
	sinsp_fdtable m_fdtable; // The fd table of this thread
	std::string m_cwd; // current working directory
	uint8_t* m_lastevent_data; // Used by some event parsers to store the last enter event

	uint16_t m_lastevent_type;
	uint16_t m_lastevent_cpuid;
	sinsp_evt::category m_lastevent_category;
	bool m_parent_loop_detected;
	blprogram* m_blprogram;

	friend class sinsp;
	friend class sinsp_parser;
	friend class sinsp_analyzer;
	friend class sinsp_analyzer_parsers;
	friend class sinsp_evt;
	friend class sinsp_thread_manager;
	friend class sinsp_transaction_table;
	friend class lua_cbacks;
	friend class sinsp_baseliner;
	friend class sinsp_cgroup; // for set_cgroups
};

/*@}*/

class threadinfo_map_t
{
public:
	typedef std::function<bool(const std::shared_ptr<sinsp_threadinfo>&)> const_shared_ptr_visitor_t;
	typedef std::function<bool(const sinsp_threadinfo&)> const_visitor_t;
	typedef std::function<bool(sinsp_threadinfo&)> visitor_t;
	typedef std::shared_ptr<sinsp_threadinfo> ptr_t;

	inline void put(ptr_t tinfo)
	{
		m_threads[tinfo->m_tid] = tinfo;
	}

	inline sinsp_threadinfo* get(uint64_t tid)
	{
		auto it = m_threads.find(tid);
		if (it == m_threads.end())
		{
			return  nullptr;
		}
		return it->second.get();
	}

	inline ptr_t get_ref(uint64_t tid)
	{
		auto it = m_threads.find(tid);
		if (it == m_threads.end())
		{
			return  nullptr;
		}
		return it->second;
	}

	inline void erase(uint64_t tid)
	{
		m_threads.erase(tid);
	}

	inline void clear()
	{
		m_threads.clear();
	}

	bool const_loop_shared_pointer(const_shared_ptr_visitor_t callback)
	{
		for (auto& it : m_threads)
		{
			if (!callback(it.second))
			{
				return false;
			}
		}
		return true;
	}

	bool const_loop(const_visitor_t callback) const
	{
		for (const auto& it : m_threads)
		{
			if (!callback(*it.second.get()))
			{
				return false;
			}
		}
		return true;
	}

	bool loop(visitor_t callback)
	{
		for (auto& it : m_threads)
		{
			if (!callback(*it.second.get()))
			{
				return false;
			}
		}
		return true;
	}

	inline size_t size() const
	{
		return m_threads.size();
	}

protected:
	std::unordered_map<int64_t, ptr_t> m_threads;
};

///////////////////////////////////////////////////////////////////////////////
// This class manages the thread table
///////////////////////////////////////////////////////////////////////////////
class SINSP_PUBLIC sinsp_thread_manager: public libsinsp::state::table<int64_t>
{
public:
	sinsp_thread_manager(sinsp* inspector);
	void clear();

	std::unique_ptr<sinsp_threadinfo> new_threadinfo() const;

	std::unique_ptr<sinsp_fdinfo> new_fdinfo() const;

	bool add_thread(sinsp_threadinfo *threadinfo, bool from_scap_proctable);
	sinsp_threadinfo* find_new_reaper(sinsp_threadinfo*);
	void remove_thread(int64_t tid);
	// Returns true if the table is actually scanned
	// NOTE: this is implemented in sinsp.cpp so we can inline it from there
	inline bool remove_inactive_threads();
	void remove_main_thread_fdtable(sinsp_threadinfo* main_thread);
	void fix_sockets_coming_from_proc();
	void reset_child_dependencies();
	void create_thread_dependencies_after_proc_scan();
	/*!
      \brief Look up a thread given its tid and return its information,
       and optionally go dig into proc if the thread is not in the thread table.

      \param tid the ID of the thread. In case of multi-thread processes,
       this corresponds to the PID.
      \param query_os_if_not_found if true, the library will search for this
       thread's information in proc, use the result to create a new thread
       entry, and return the new entry.

      \return the \ref sinsp_threadinfo object containing full thread information
       and state.

      \note if you are interested in a process' information, just give this
      function with the PID of the process.

      @throws a sinsp_exception containing the error string is thrown in case
       of failure.
    */

	threadinfo_map_t::ptr_t get_thread_ref(int64_t tid, bool query_os_if_not_found = false, bool lookup_only = true, bool main_thread=false);

	//
    // Note: lookup_only should be used when the query for the thread is made
    //       not as a consequence of an event for that thread arriving, but
    //       just for lookup reason. In that case, m_lastaccess_ts is not updated
    //       and m_last_tinfo is not set.
    //
    threadinfo_map_t::ptr_t find_thread(int64_t tid, bool lookup_only);


	void dump_threads_to_file(scap_dumper_t* dumper);

	uint32_t get_thread_count()
	{
		return (uint32_t)m_threadtable.size();
	}

	threadinfo_map_t* get_threads()
	{
		return &m_threadtable;
	}

	std::set<uint16_t> m_server_ports;

	void set_max_thread_table_size(uint32_t value);

	int32_t get_m_n_proc_lookups() const { return m_n_proc_lookups; }
	int32_t get_m_n_main_thread_lookups() const { return m_n_main_thread_lookups; }
	uint64_t get_m_n_proc_lookups_duration_ns() const { return m_n_proc_lookups_duration_ns; }
	void reset_thread_counters() { m_n_proc_lookups = 0; m_n_main_thread_lookups = 0; m_n_proc_lookups_duration_ns = 0; }

	void set_m_max_n_proc_lookups(int32_t val) { m_max_n_proc_lookups = val; }
	void set_m_max_n_proc_socket_lookups(int32_t val) { m_max_n_proc_socket_lookups = val; }

	// ---- libsinsp::state::table implementation ----

	size_t entries_count() const override
	{
		return m_threadtable.size();
	}

	void clear_entries() override
	{
		m_threadtable.clear();
	}

	std::unique_ptr<libsinsp::state::table_entry> new_entry() const override;

	bool foreach_entry(std::function<bool(libsinsp::state::table_entry& e)> pred) override
	{
		return m_threadtable.loop([&pred](sinsp_threadinfo& e){ return pred(e); });
	}

	std::shared_ptr<libsinsp::state::table_entry> get_entry(const int64_t& key) override
	{
		return find_thread(key, false);
	}

	std::shared_ptr<libsinsp::state::table_entry> add_entry(const int64_t& key, std::unique_ptr<libsinsp::state::table_entry> entry) override
	{
		if (!entry)
		{
			throw sinsp_exception("null entry added to thread table");
		}
		auto tinfo = dynamic_cast<sinsp_threadinfo*>(entry.get());
		if (!tinfo)
		{
			throw sinsp_exception("unknown entry type added to thread table");
		}
		entry.release();
		tinfo->m_tid = key;
		add_thread(tinfo, false);
		return get_entry(key);
	}

	bool erase_entry(const int64_t& key) override
	{
		// todo(jasondellaluce): should we trigger the whole removal logic,
		// or should we just erase the table entry?
		// todo(jasondellaluce): should we make m_tid_to_remove a list, in case
		// we have more than one thread removed in a given event loop iteration?
		if(m_threadtable.get(key))
		{
			this->remove_thread(key);
			return true;
		}
		return false;
	}

	inline std::shared_ptr<thread_group_info> get_thread_group_info(int64_t pid) const
	{
		auto tgroup = m_thread_groups.find(pid);
		if(tgroup != m_thread_groups.end())
		{
			return tgroup->second;
		}
		return nullptr;
	}

	inline void set_thread_group_info(int64_t pid, const std::shared_ptr<thread_group_info>& tginfo)
	{
		/* It should be impossible to have a pid conflict...
		 * Right now we manage it but we could also remove it.
		 */
		auto ret = m_thread_groups.insert({pid, tginfo});
		if(!ret.second)
		{
			m_thread_groups.erase(ret.first);
			m_thread_groups.insert({pid, tginfo});
		}
	}

VISIBILITY_PRIVATE
	void create_thread_dependencies(const std::shared_ptr<sinsp_threadinfo>& tinfo);
	inline void clear_thread_pointers(sinsp_threadinfo& threadinfo);
	void free_dump_fdinfos(std::vector<scap_fdinfo*>* fdinfos_to_free);
	void thread_to_scap(sinsp_threadinfo& tinfo, scap_threadinfo* sctinfo);

	sinsp* m_inspector;
	/* the key is the pid of the group, and the value is a shared pointer to the thread_group_info */
	std::unordered_map<int64_t, std::shared_ptr<thread_group_info>> m_thread_groups;
	threadinfo_map_t m_threadtable;
	int64_t m_last_tid;
	std::weak_ptr<sinsp_threadinfo> m_last_tinfo;
	uint64_t m_last_flush_time_ns;
	// Increased legacy default of 131072 in January 2024 to prevent
	// possible drops due to full threadtable on more modern servers
	const uint32_t m_thread_table_absolute_max_size = 262144;
	uint32_t m_max_thread_table_size;
	int32_t m_n_proc_lookups = 0;
	uint64_t m_n_proc_lookups_duration_ns = 0;
	int32_t m_n_main_thread_lookups = 0;
	int32_t m_max_n_proc_lookups = -1;
	int32_t m_max_n_proc_socket_lookups = -1;

	friend class sinsp_parser;
	friend class sinsp_analyzer;
	friend class sinsp;
	friend class sinsp_threadinfo;
	friend class sinsp_baseliner;
};

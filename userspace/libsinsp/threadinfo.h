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

#ifdef _WIN32
struct iovec {
	void* iov_base; /* Starting address */
	size_t iov_len; /* Number of bytes to transfer */
};
#else
#include <sys/uio.h>
#endif

#include <functional>
#include <memory>
#include <libsinsp/sinsp_fdtable_factory.h>
#include <libsinsp/fdtable.h>
#include <libsinsp/thread_group_info.h>
#include <libsinsp/state/table.h>
#include <libsinsp/state/table_adapters.h>
#include <libsinsp/event.h>
#include <libsinsp/filter.h>
#include <libsinsp/ifinfo.h>
#include <libscap/scap_savefile_api.h>

struct erase_fd_params {
	bool m_remove_from_table;
	int64_t m_fd;
	sinsp_threadinfo* m_tinfo;
	sinsp_fdinfo* m_fdinfo;
};

/** @defgroup state State management
 *  @{
 */

/*!
  \brief Container holding parameters to be provided to sinsp_threadinfo constructor.
  An instance of this struct is meant to be shared among all sinsp_threadinfo instances.
*/
struct sinsp_threadinfo_ctor_params {
	// The following fields are externally provided and access to them is expected to be
	// read-only.
	const sinsp_network_interfaces& network_interfaces;
	const sinsp_fdinfo_factory& fdinfo_factory;
	const sinsp_fdtable_factory& fdtable_factory;
	const std::shared_ptr<libsinsp::state::dynamic_field_infos>& thread_manager_dyn_fields;
};

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
class SINSP_PUBLIC sinsp_threadinfo : public libsinsp::state::extensible_struct {
public:
	using ctor_params = sinsp_threadinfo_ctor_params;

	explicit sinsp_threadinfo(const std::shared_ptr<ctor_params>& params);
	~sinsp_threadinfo() override;

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

	inline void set_cwd(const std::string& v) { m_cwd = v; }

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
	  \brief Return concatenated environment variables with the format of "ENV_NAME=value
	  ENV_NAME1=value1" ...
	*/
	std::string concatenate_all_env();

	/*!
	  \brief Return true if this is a process' main thread.
	*/
	inline bool is_main_thread() const {
		return (m_tid == m_pid) || m_flags & PPM_CL_IS_MAIN_THREAD;
	}

	/*!
	  \brief Return true if this thread belongs to a pid namespace.
	*/
	inline bool is_in_pid_namespace() const {
		// m_tid should be always valid because we read it from the scap event header
		return (m_flags & PPM_CL_CHILD_IN_PIDNS || (m_tid != m_vtid && m_vtid >= 0));
	}

	/*!
	  \brief Return true if the thread is invalid. Sometimes we create some
	  invalid thread info, if we are not able to scan proc.
	*/
	inline bool is_invalid() const { return m_tid < 0 || m_pid < 0 || m_ptid < 0; }

	/*!
	  \brief Return true if the thread is dead.
	*/
	inline bool is_dead() const { return m_flags & PPM_CL_CLOSED; }

	/*!
	  \brief Mark thread as dead.
	*/
	inline void set_dead() { m_flags |= PPM_CL_CLOSED; }

	/*!
	  \brief In some corner cases is possible that a dead main thread could
	  become again alive. For example, when an execve is performed by a secondary
	  thread and the main thread is already dead
	*/
	inline void resurrect_thread() {
		/* If the thread is not dead we do nothing.
		 * It should never happen
		 */
		if(!is_dead()) {
			return;
		}

		m_flags &= ~PPM_CL_CLOSED;
		if(!m_tginfo) {
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
	inline uint64_t get_num_threads() const { return m_tginfo ? m_tginfo->get_thread_count() : 0; }

	/*!
	    \brief Return the number of alive threads in the thread group, excluding the thread leader.
	*/
	inline uint64_t get_num_not_leader_threads() const {
		if(!m_tginfo) {
			return 0;
		}

		auto main_thread = get_main_thread();
		if(main_thread != nullptr && !main_thread->is_dead()) {
			return m_tginfo->get_thread_count() - 1;
		}
		/* we don't have the main thread in the group or it is dead */
		return m_tginfo->get_thread_count();
	}

	/*
	  \brief returns true if there is a loop detected in the thread parent state.
	  Needs traverse_parent_state() to have been called first.
	*/
	inline bool parent_loop_detected() const { return m_parent_loop_detected; }

	inline void set_parent_loop_detected(bool v) { m_parent_loop_detected = v; }

	/*!
	  \brief Get the main thread of the process containing this thread.
	*/
	inline sinsp_threadinfo* get_main_thread() {
		if(is_main_thread()) {
			return this;
		}

		// This is possible when we have invalid threads
		if(m_tginfo == nullptr) {
			return nullptr;
		}

		// If we have the main thread in the group, it is always the first one
		auto possible_main = m_tginfo->get_first_thread();
		if(possible_main == nullptr || !possible_main->is_main_thread()) {
			return nullptr;
		}
		return possible_main;
	}

	inline const sinsp_threadinfo* get_main_thread() const {
		return const_cast<sinsp_threadinfo*>(this)->get_main_thread();
	}

	/*!
	  \brief Retrieve information about one of this thread/process FDs.

	  \param fd The file descriptor number, e.g. 0 for stdin.

	  \return Pointer to the FD information, or NULL if the given FD doesn't
	   exist
	*/
	inline sinsp_fdinfo* get_fd(int64_t fd) {
		if(fd < 0) {
			return NULL;
		}

		sinsp_fdtable* fdt = get_fd_table();

		if(fdt) {
			sinsp_fdinfo* fdinfo = fdt->find(fd);
			if(fdinfo) {
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

	void report_thread_loop(const sinsp_threadinfo& looping_thread);

	void assign_children_to_reaper(sinsp_threadinfo* reaper);

	inline void add_child(const std::shared_ptr<sinsp_threadinfo>& child) {
		m_children.push_front(child);
		/* Set current thread as parent */
		child->m_ptid = m_tid;
		/* Increment the number of not expired children */
		m_not_expired_children++;
	}

	inline void clean_expired_children() {
		auto child = m_children.begin();
		while(child != m_children.end()) {
			/* This child is expired */
			if(child->expired()) {
				/* `erase` returns the pointer to the next child
				 * no need for manual increment.
				 */
				child = m_children.erase(child);
				continue;
			}
			child++;
		}
	}

	static void populate_cmdline(std::string& cmdline, const sinsp_threadinfo* tinfo);
	static void populate_args(std::string& args, const sinsp_threadinfo* tinfo);

	/*!
	  \brief Translate a directory's file descriptor into its path
	  \param dir_fd  A file descriptor for a directory
	  \return  A path (or "" if failure)
	 */
	std::string get_path_for_dir_fd(int64_t dir_fd);

	using cgroups_t = std::vector<std::pair<std::string, std::string>>;
	const cgroups_t& cgroups() const;

	//
	// Core state
	//
	int64_t m_tid;   ///< The id of this thread
	int64_t m_pid;   ///< The id of the process containing this thread. In single thread threads,
	                 ///< this is equal to tid.
	int64_t m_ptid;  ///< The id of the process that started this thread.
	int64_t m_reaper_tid;   ///< The id of the reaper for this thread
	int64_t m_sid;          ///< The session id of the process containing this thread.
	std::string m_comm;     ///< Command name (e.g. "top")
	std::string m_exe;      ///< argv[0] (e.g. "sshd: user@pts/4")
	std::string m_exepath;  ///< full executable path
	bool m_exe_writable;
	bool m_exe_upper_layer;  ///< True if the executable file belongs to upper layer in overlayfs
	bool m_exe_lower_layer;  ///< True if the executable file belongs to lower layer in overlayfs
	bool m_exe_from_memfd;   ///< True if the executable is stored in fileless memory referenced by
	                         ///< memfd
	std::vector<std::string> m_args;  ///< Command line arguments (e.g. "-d1")
	std::vector<std::string> m_env;   ///< Environment variables
	cgroups_t m_cgroups;              ///< subsystem-cgroup pairs
	uint32_t m_flags;   ///< The thread flags. See the PPM_CL_* declarations in ppm_events_public.h.
	int64_t m_fdlimit;  ///< The maximum number of FDs this thread can open
	uint32_t m_uid;     ///< uid
	uint32_t m_gid;     ///< gid
	uint32_t m_loginuid;         ///< loginuid
	uint64_t m_cap_permitted;    ///< permitted capabilities
	uint64_t m_cap_effective;    ///< effective capabilities
	uint64_t m_cap_inheritable;  ///< inheritable capabilities
	uint64_t m_exe_ino;          ///< executable inode ino
	uint64_t m_exe_ino_ctime;    ///< executable inode ctime (last status change time)
	uint64_t m_exe_ino_mtime;    ///< executable inode mtime (last modification time)
	uint64_t m_exe_ino_ctime_duration_clone_ts;  ///< duration in ns between executable inode ctime
	                                             ///< (last status change time) and clone_ts
	uint64_t m_exe_ino_ctime_duration_pidns_start;  ///< duration in ns between pidns start ts and
	                                                ///< executable inode ctime (last status change
	                                                ///< time) if pidns start predates ctime
	uint32_t m_vmsize_kb;                           ///< total virtual memory (as kb).
	uint32_t m_vmrss_kb;                            ///< resident non-swapped memory (as kb).
	uint32_t m_vmswap_kb;                           ///< swapped memory (as kb).
	uint64_t m_pfmajor;                             ///< number of major page faults since start.
	uint64_t m_pfminor;                             ///< number of minor page faults since start.
	int64_t m_vtid;                                 ///< The virtual id of this thread.
	int64_t m_vpid;   ///< The virtual id of the process containing this thread. In single thread
	                  ///< threads, this is equal to vtid.
	int64_t m_vpgid;  // The virtual process group id, as seen from its pid namespace
	int64_t m_pgid;   // Process group id, as seen from the host pid namespace
	uint64_t m_pidns_init_start_ts;  ///< The pid_namespace init task (child_reaper) start_time ts.
	std::string m_root;

	uint32_t m_tty;  ///< Number of controlling terminal
	std::shared_ptr<thread_group_info> m_tginfo;
	std::list<std::weak_ptr<sinsp_threadinfo>> m_children;
	uint64_t m_not_expired_children;
	std::string m_cmd_line;
	bool m_filtered_out;  ///< True if this thread is filtered out by the inspector filter from
	                      ///< saving to a capture

	//
	// State for multi-event processing
	//
	int64_t m_lastevent_fd;    ///< The FD os the last event used by this thread.
	uint64_t m_lastevent_ts;   ///< timestamp of the last event for this thread.
	uint64_t m_prevevent_ts;   ///< timestamp of the event before the last for this thread.
	uint64_t m_lastaccess_ts;  ///< The last time this thread was looked up. Used when cleaning up
	                           ///< the table.
	uint64_t m_clone_ts;       ///< When the clone that started this process happened.
	uint64_t m_lastexec_ts;    ///< The last time exec was called

	size_t args_len() const;
	size_t env_len() const;

	void args_to_iovec(struct iovec** iov, int* iovcnt, std::string& rem) const;

	void env_to_iovec(struct iovec** iov, int* iovcnt, std::string& rem) const;

	void cgroups_to_iovec(struct iovec** iov,
	                      int* iovcnt,
	                      std::string& rem,
	                      const cgroups_t& cgroups) const;

	/* Note that `fd_table` should be shared with the main thread only if `PPM_CL_CLONE_FILES`
	 * is specified. Today we always specify `PPM_CL_CLONE_FILES` for all threads.
	 */
	inline sinsp_fdtable* get_fd_table() {
		if(!(m_flags & PPM_CL_CLONE_FILES)) {
			return &m_fdtable;
		} else {
			sinsp_threadinfo* root = get_main_thread();
			return (root == nullptr) ? nullptr : &(root->get_fdtable());
		}
	}

	inline const sinsp_fdtable* get_fd_table() const {
		return const_cast<sinsp_threadinfo*>(this)->get_fd_table();
	}

	void init();
	void init(const scap_threadinfo& pinfo, bool can_load_env_from_proc);
	void fix_sockets_coming_from_proc(const std::set<uint16_t>& ipv4_server_ports,
	                                  bool resolve_hostname_and_port);
	sinsp_fdinfo* add_fd(int64_t fd, std::shared_ptr<sinsp_fdinfo>&& fdinfo);
	sinsp_fdinfo* add_fd_from_scap(const scap_fdinfo& fdi, bool resolve_hostname_and_port);
	void remove_fd(int64_t fd);
	void update_cwd(std::string_view cwd);
	void set_args(const char* args, size_t len);
	void set_args(const std::vector<std::string>& args);
	void set_env(const char* env, size_t len, bool can_load_from_proc);
	void set_cgroups(const char* cgroups, size_t len);
	void set_cgroups(const std::vector<std::string>& cgroups);
	void set_cgroups(const cgroups_t& cgroups);
	bool is_lastevent_data_valid() const;
	inline void set_lastevent_data_validity(bool isvalid) {
		if(isvalid) {
			m_lastevent_cpuid = (uint16_t)1;
		} else {
			m_lastevent_cpuid = (uint16_t)-1;
		}
	}

	inline const uint8_t* get_last_event_data() const { return m_lastevent_data; }

	inline uint8_t* get_last_event_data() { return m_lastevent_data; }

	inline void set_last_event_data(uint8_t* v) { m_lastevent_data = v; }

	inline const sinsp_fdtable& get_fdtable() const { return m_fdtable; }

	inline sinsp_fdtable& get_fdtable() { return m_fdtable; }

	inline uint16_t get_lastevent_type() const { return m_lastevent_type; }

	inline void set_lastevent_type(uint16_t v) { m_lastevent_type = v; }

	inline uint16_t get_lastevent_cpuid() const { return m_lastevent_cpuid; }

	inline void set_lastevent_cpuid(uint16_t v) { m_lastevent_cpuid = v; }

	inline const sinsp_evt::category& get_lastevent_category() const {
		return m_lastevent_category;
	}

	inline sinsp_evt::category& get_lastevent_category() { return m_lastevent_category; }

	inline void update_main_fdtable() {
		auto fdtable = get_fd_table();
		m_main_fdtable =
		        !fdtable ? nullptr
		                 : static_cast<const libsinsp::state::base_table*>(fdtable->table_ptr());
	}

	void set_exepath(std::string&& exepath);

	/*!
	  \brief A static version of static_fields()
	  \return The group of field infos available.
	 */
	static libsinsp::state::static_field_infos get_static_fields();

protected:
	// Parameters provided at thread info construction phase.
	// Notice: the struct instance is shared among all the thread info instances.
	// Notice 2: this should be a plain const reference, but use a shared_ptr or the compiler will
	// complain about referencing a member (m_input_plugin) whose lifetime is shorter than the
	// ctor_params object in sinsp constructor.
	const std::shared_ptr<ctor_params> m_params;

private:
	sinsp_threadinfo* get_cwd_root();
	bool set_env_from_proc();
	size_t strvec_len(const std::vector<std::string>& strs) const;
	void strvec_to_iovec(const std::vector<std::string>& strs,
	                     struct iovec** iov,
	                     int* iovcnt,
	                     std::string& rem) const;

	void add_to_iovec(const std::string& str,
	                  const bool include_trailing_null,
	                  struct iovec& iov,
	                  uint32_t& alen,
	                  std::string& rem) const;

	//
	// Parameters that can't be accessed directly because they could be in the
	// parent thread info
	//
	sinsp_fdtable m_fdtable;  // The fd table of this thread
	const libsinsp::state::base_table*
	        m_main_fdtable;     // Points to the base fd table of the current main thread
	std::string m_cwd;          // current working directory
	uint8_t* m_lastevent_data;  // Used by some event parsers to store the last enter event

	uint16_t m_lastevent_type;
	uint16_t m_lastevent_cpuid;
	sinsp_evt::category m_lastevent_category;
	bool m_parent_loop_detected;
	libsinsp::state::stl_container_table_adapter<decltype(m_args)> m_args_table_adapter;
	libsinsp::state::stl_container_table_adapter<decltype(m_env)> m_env_table_adapter;
	libsinsp::state::stl_container_table_adapter<
	        decltype(m_cgroups),
	        libsinsp::state::pair_table_entry_adapter<std::string, std::string>>
	        m_cgroups_table_adapter;
};

/*@}*/

class threadinfo_map_t {
public:
	typedef std::function<bool(const std::shared_ptr<sinsp_threadinfo>&)>
	        const_shared_ptr_visitor_t;
	typedef std::function<bool(const sinsp_threadinfo&)> const_visitor_t;
	typedef std::function<bool(sinsp_threadinfo&)> visitor_t;
	typedef std::shared_ptr<sinsp_threadinfo> ptr_t;

	inline const ptr_t& put(const ptr_t& tinfo) {
		m_threads[tinfo->m_tid] = tinfo;
		return m_threads[tinfo->m_tid];
	}

	inline sinsp_threadinfo* get(uint64_t tid) {
		auto it = m_threads.find(tid);
		if(it == m_threads.end()) {
			return nullptr;
		}
		return it->second.get();
	}

	inline const ptr_t& get_ref(uint64_t tid) {
		auto it = m_threads.find(tid);
		if(it == m_threads.end()) {
			return m_nullptr_ret;
		}
		return it->second;
	}

	inline void erase(uint64_t tid) { m_threads.erase(tid); }

	inline void clear() { m_threads.clear(); }

	bool const_loop_shared_pointer(const_shared_ptr_visitor_t callback) {
		for(auto& it : m_threads) {
			if(!callback(it.second)) {
				return false;
			}
		}
		return true;
	}

	bool const_loop(const_visitor_t callback) const {
		for(const auto& it : m_threads) {
			if(!callback(*it.second)) {
				return false;
			}
		}
		return true;
	}

	bool loop(visitor_t callback) {
		for(auto& it : m_threads) {
			if(!callback(*it.second)) {
				return false;
			}
		}
		return true;
	}

	inline size_t size() const { return m_threads.size(); }

protected:
	std::unordered_map<int64_t, ptr_t> m_threads;
	const ptr_t m_nullptr_ret;  // needed for returning a reference
};

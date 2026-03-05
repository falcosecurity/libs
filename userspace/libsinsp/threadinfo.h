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
#include <mutex>
#include <shared_mutex>
#include <libsinsp/atomic_helpers.h>
#include <libsinsp/sinsp_fdtable_factory.h>
#include <libsinsp/fdtable.h>
#include <libsinsp/thread_group_info.h>
#include <libsinsp/state/table.h>
#include <libsinsp/state/table_adapters.h>
#include <libsinsp/event.h>
#include <libsinsp/filter.h>
#include <libsinsp/ifinfo.h>
#include <libscap/scap_savefile_api.h>
#include <optional>

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

/*!
  \brief Parameter object for applying execve/execveat exit state (mutex-protected fields only).
  Used by parse_execve_exit to update thread state under a single lock so concurrent
  readers never see a half-updated exec-info group. Atomic-backed fields (pid, flags,
  uid, gid, etc.) are updated by the parser via individual accessors.
*/
struct SINSP_PUBLIC sinsp_threadinfo_exec_state {
	std::string exe;
	uint64_t lastexec_ts{0};
	std::string comm;
	std::vector<std::string> args;
	std::optional<std::vector<std::string>> env;
	bool load_env_from_proc{false};
	std::optional<std::vector<std::pair<std::string, std::string>>> cgroups;
	std::optional<std::string> exepath;
	std::optional<bool> exe_writable;
	std::optional<bool> exe_upper_layer;
	std::optional<bool> exe_from_memfd;
	std::optional<bool> exe_lower_layer;
	std::optional<uint64_t> exe_ino;
	std::optional<uint64_t> exe_ino_ctime;
	std::optional<uint64_t> exe_ino_mtime;
	std::optional<uint64_t> exe_ino_ctime_duration_clone_ts;
	std::optional<uint64_t> exe_ino_ctime_duration_pidns_start;
};

class SINSP_PUBLIC sinsp_threadinfo : public libsinsp::state::table_entry {
public:
	using ctor_params = sinsp_threadinfo_ctor_params;
	using exec_state_t = sinsp_threadinfo_exec_state;

	explicit sinsp_threadinfo(const std::shared_ptr<ctor_params>& params);
	~sinsp_threadinfo() override;

	libsinsp::state::extensible_struct::field_infos static_fields() const override;

	/*!
	  \brief Return the working directory of the process containing this thread.
	*/
	std::string get_cwd();

	inline void set_cwd(const std::string& v) {
		std::unique_lock l(m_state_mutex);
		m_cwd = v;
	}

	/*!
	  \brief Return the values of all environment variables for the process
	  containing this thread.
	*/
	std::vector<std::string> get_env();

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
		return (m_tid == get_pid()) || get_flags() & PPM_CL_IS_MAIN_THREAD;
	}

	/*!
	  \brief Return true if this thread belongs to a pid namespace.
	*/
	inline bool is_in_pid_namespace() const {
		return (get_flags() & PPM_CL_CHILD_IN_PIDNS || (m_tid != get_vtid() && get_vtid() >= 0));
	}

	/*!
	  \brief Return true if the thread is invalid. Sometimes we create some
	  invalid thread info, if we are not able to scan proc.
	*/
	inline bool is_invalid() const { return m_tid < 0 || get_pid() < 0 || get_ptid() < 0; }

	/*!
	  \brief Return true if the thread is dead.
	*/
	inline bool is_dead() const { return get_flags() & PPM_CL_CLOSED; }

	/*!
	  \brief Mark thread as dead.
	*/
	inline void set_dead() { or_flags(PPM_CL_CLOSED); }

	/*!
	  \brief In some corner cases is possible that a dead main thread could
	  become again alive. For example, when an execve is performed by a secondary
	  thread and the main thread is already dead
	*/
	inline void resurrect_thread() {
		if(!is_dead()) {
			return;
		}

		clear_flags(PPM_CL_CLOSED);
		auto tgi = get_tginfo();
		if(!tgi) {
			return;
		}
		tgi->increment_thread_count();
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
	inline std::shared_ptr<sinsp_threadinfo> get_main_thread() {
		if(is_main_thread()) {
			return std::shared_ptr<sinsp_threadinfo>(std::shared_ptr<void>{}, this);
		}

		auto tgi = get_tginfo();
		if(tgi == nullptr) {
			return nullptr;
		}

		auto possible_main = tgi->get_first_thread();
		if(!possible_main || !possible_main->is_main_thread()) {
			return nullptr;
		}
		return possible_main;
	}

	inline std::shared_ptr<const sinsp_threadinfo> get_main_thread() const {
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
				fdinfo->snapshot_oldname();
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
		std::unique_lock lock(m_children_mutex);
		m_children.push_front(child);
		child->set_ptid(m_tid);
		m_not_expired_children++;
	}

	inline void remove_child_from_list(const std::shared_ptr<sinsp_threadinfo>& child) {
		std::unique_lock lock(m_children_mutex);
		remove_child_from_list_unlocked(child);
	}

	inline void remove_child_and_maybe_clean(const std::shared_ptr<sinsp_threadinfo>& child) {
		std::unique_lock lock(m_children_mutex);
		remove_child_from_list_unlocked(child);
		if((m_children.size() - m_not_expired_children) >= DEFAULT_EXPIRED_CHILDREN_THRESHOLD) {
			clean_expired_children_unlocked();
		}
	}

	inline void clean_expired_children() {
		std::unique_lock lock(m_children_mutex);
		clean_expired_children_unlocked();
	}

	inline bool has_children() const {
		std::unique_lock lock(m_children_mutex);
		return !m_children.empty();
	}

	template<typename F>
	inline void for_each_child(F&& fn) {
		std::unique_lock lock(m_children_mutex);
		for(auto& child : m_children) {
			if(auto ptr = child.lock()) {
				fn(ptr);
			}
		}
	}

	inline void set_not_expired_children(uint64_t v) { m_not_expired_children = v; }

	inline uint64_t get_not_expired_children() const { return m_not_expired_children; }

	inline size_t get_children_count() const {
		std::unique_lock lock(m_children_mutex);
		return m_children.size();
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
	cgroups_t get_cgroups() const;
	const cgroups_t& cgroups() const;

	//
	// Immutable identity (safe without synchronization after table insertion)
	//
	int64_t m_tid;                   ///< The id of this thread
	uint64_t m_pidns_init_start_ts;  ///< The pid_namespace init task (child_reaper) start_time ts.

	// --- Atomic identity getters/setters ---
	inline int64_t get_pid() const { return load_relaxed(m_pid); }
	inline void set_pid(int64_t v) { store_relaxed(m_pid, v); }
	inline int64_t get_ptid() const { return load_relaxed(m_ptid); }
	inline void set_ptid(int64_t v) { store_relaxed(m_ptid, v); }
	inline int64_t get_reaper_tid() const { return load_relaxed(m_reaper_tid); }
	inline void set_reaper_tid(int64_t v) { store_relaxed(m_reaper_tid, v); }
	inline int64_t get_sid() const { return load_relaxed(m_sid); }
	inline void set_sid(int64_t v) { store_relaxed(m_sid, v); }
	inline int64_t get_vtid() const { return load_relaxed(m_vtid); }
	inline void set_vtid(int64_t v) { store_relaxed(m_vtid, v); }
	inline int64_t get_vpid() const { return load_relaxed(m_vpid); }
	inline void set_vpid(int64_t v) { store_relaxed(m_vpid, v); }
	inline int64_t get_vpgid() const { return load_relaxed(m_vpgid); }
	inline void set_vpgid(int64_t v) { store_relaxed(m_vpgid, v); }
	inline int64_t get_pgid() const { return load_relaxed(m_pgid); }
	inline void set_pgid(int64_t v) { store_relaxed(m_pgid, v); }

	// --- Atomic flags ---
	inline uint32_t get_flags() const { return load_relaxed(m_flags); }
	inline void set_flags(uint32_t v) { store_relaxed(m_flags, v); }
	inline void or_flags(uint32_t v) { fetch_or_relaxed(m_flags, v); }
	inline void clear_flags(uint32_t mask) { fetch_and_relaxed(m_flags, ~mask); }

	// --- Atomic credential/resource getters/setters ---
	inline int64_t get_fdlimit() const { return load_relaxed(m_fdlimit); }
	inline void set_fdlimit(int64_t v) { store_relaxed(m_fdlimit, v); }
	inline uint32_t get_uid() const { return load_relaxed(m_uid); }
	inline void set_uid(uint32_t v) { store_relaxed(m_uid, v); }
	inline uint32_t get_gid() const { return load_relaxed(m_gid); }
	inline void set_gid(uint32_t v) { store_relaxed(m_gid, v); }
	inline uint32_t get_loginuid() const { return load_relaxed(m_loginuid); }
	inline void set_loginuid(uint32_t v) { store_relaxed(m_loginuid, v); }
	inline uint64_t get_cap_permitted() const { return load_relaxed(m_cap_permitted); }
	inline void set_cap_permitted(uint64_t v) { store_relaxed(m_cap_permitted, v); }
	inline uint64_t get_cap_effective() const { return load_relaxed(m_cap_effective); }
	inline void set_cap_effective(uint64_t v) { store_relaxed(m_cap_effective, v); }
	inline uint64_t get_cap_inheritable() const { return load_relaxed(m_cap_inheritable); }
	inline void set_cap_inheritable(uint64_t v) { store_relaxed(m_cap_inheritable, v); }
	inline uint32_t get_tty() const { return load_relaxed(m_tty); }
	inline void set_tty(uint32_t v) { store_relaxed(m_tty, v); }
	inline bool get_filtered_out() const { return load_relaxed(m_filtered_out); }
	inline void set_filtered_out(bool v) { store_relaxed(m_filtered_out, v); }

	inline uint32_t get_vmsize_kb() const { return load_relaxed(m_vmsize_kb); }
	inline void set_vmsize_kb(uint32_t v) { store_relaxed(m_vmsize_kb, v); }
	inline uint32_t get_vmrss_kb() const { return load_relaxed(m_vmrss_kb); }
	inline void set_vmrss_kb(uint32_t v) { store_relaxed(m_vmrss_kb, v); }
	inline uint32_t get_vmswap_kb() const { return load_relaxed(m_vmswap_kb); }
	inline void set_vmswap_kb(uint32_t v) { store_relaxed(m_vmswap_kb, v); }
	inline uint64_t get_pfmajor() const { return load_relaxed(m_pfmajor); }
	inline void set_pfmajor(uint64_t v) { store_relaxed(m_pfmajor, v); }
	inline uint64_t get_pfminor() const { return load_relaxed(m_pfminor); }
	inline void set_pfminor(uint64_t v) { store_relaxed(m_pfminor, v); }

	// --- Mutex-protected exec-info getters/setters ---
	std::string get_comm() const;
	void set_comm(std::string v);
	std::string get_exe() const;
	void set_exe(std::string v);
	std::string get_exepath() const;
	bool get_exe_writable() const;
	void set_exe_writable(bool v);
	bool get_exe_upper_layer() const;
	void set_exe_upper_layer(bool v);
	bool get_exe_lower_layer() const;
	void set_exe_lower_layer(bool v);
	bool get_exe_from_memfd() const;
	void set_exe_from_memfd(bool v);
	std::vector<std::string> get_args() const;
	std::string get_cmd_line() const;
	std::string get_root() const;
	void set_root(std::string v);
	uint64_t get_exe_ino() const;
	void set_exe_ino(uint64_t v);
	uint64_t get_exe_ino_ctime() const;
	void set_exe_ino_ctime(uint64_t v);
	uint64_t get_exe_ino_mtime() const;
	void set_exe_ino_mtime(uint64_t v);
	uint64_t get_exe_ino_ctime_duration_clone_ts() const;
	void set_exe_ino_ctime_duration_clone_ts(uint64_t v);
	uint64_t get_exe_ino_ctime_duration_pidns_start() const;
	void set_exe_ino_ctime_duration_pidns_start(uint64_t v);
	void set_env(const std::vector<std::string>& env);

	// --- Atomic tginfo getter/setter ---
	inline std::shared_ptr<thread_group_info> get_tginfo() const {
		return std::atomic_load(&m_tginfo);
	}
	inline void set_tginfo(std::shared_ptr<thread_group_info> v) {
		std::atomic_store(&m_tginfo, std::move(v));
	}

	// Multi-event processing state accessors (private fields, synchronized via relaxed atomics)
	inline int64_t get_lastevent_fd() const { return load_relaxed(m_lastevent_fd); }
	inline void set_lastevent_fd(int64_t v) { store_relaxed(m_lastevent_fd, v); }

	inline uint64_t get_lastevent_ts() const { return load_relaxed(m_lastevent_ts); }
	inline void set_lastevent_ts(uint64_t v) { store_relaxed(m_lastevent_ts, v); }

	inline uint64_t get_prevevent_ts() const { return load_relaxed(m_prevevent_ts); }
	inline void set_prevevent_ts(uint64_t v) { store_relaxed(m_prevevent_ts, v); }

	inline uint64_t get_lastaccess_ts() const { return load_relaxed(m_lastaccess_ts); }
	inline void set_lastaccess_ts(uint64_t v) { store_relaxed(m_lastaccess_ts, v); }

	inline uint64_t get_clone_ts() const { return load_relaxed(m_clone_ts); }
	inline void set_clone_ts(uint64_t v) { store_relaxed(m_clone_ts, v); }

	uint64_t get_lastexec_ts() const;
	void set_lastexec_ts(uint64_t v);

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
		if(!(load_relaxed(m_flags) & PPM_CL_CLONE_FILES)) {
			return &m_fdtable;
		} else {
			auto root = get_main_thread();
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
		store_relaxed(m_lastevent_cpuid, isvalid ? (uint16_t)1 : (uint16_t)-1);
	}

	inline const uint8_t* get_last_event_data() const { return m_lastevent_data; }

	inline uint8_t* get_last_event_data() { return m_lastevent_data; }

	inline void set_last_event_data(uint8_t* v) { store_relaxed(m_lastevent_data, v); }

	inline const sinsp_fdtable& get_fdtable() const { return m_fdtable; }

	inline sinsp_fdtable& get_fdtable() { return m_fdtable; }

	inline uint16_t get_lastevent_type() const { return load_relaxed(m_lastevent_type); }

	inline void set_lastevent_type(uint16_t v) { store_relaxed(m_lastevent_type, v); }

	inline uint16_t get_lastevent_cpuid() const { return load_relaxed(m_lastevent_cpuid); }

	inline void set_lastevent_cpuid(uint16_t v) { store_relaxed(m_lastevent_cpuid, v); }

	inline const sinsp_evt::category& get_lastevent_category() const {
		return m_lastevent_category;
	}

	inline sinsp_evt::category& get_lastevent_category() { return m_lastevent_category; }

	inline void update_main_fdtable() {
		auto fdtable = get_fd_table();
		auto val = !fdtable ? nullptr
		                    : static_cast<const libsinsp::state::base_table*>(fdtable->table_ptr());
		store_relaxed(m_main_fdtable, val);
	}

	void set_exepath(std::string&& exepath);

	/*!
	  \brief Apply execve/execveat exit state (mutex-protected fields only) under a single lock.
	  \param state The new mutex-protected state built from the execve exit event.
	  */
	void apply_exec_state(const exec_state_t& state);

	/*!
	  \brief Parse cgroup definitions (e.g. from execve exit param) into cgroups_t.
	  */
	static cgroups_t parse_cgroups(const std::vector<std::string>& defs);

	/*!
	  \brief A static version of static_fields()
	  \return The group of field infos available.
	 */
	static extensible_struct::field_infos get_static_fields();

protected:
	// Parameters provided at thread info construction phase.
	// Notice: the struct instance is shared among all the thread info instances.
	// Notice 2: this should be a plain const reference, but use a shared_ptr or the compiler will
	// complain about referencing a member (m_input_plugin) whose lifetime is shorter than the
	// ctor_params object in sinsp constructor.
	const std::shared_ptr<ctor_params> m_params;

	inline void remove_child_from_list_unlocked(const std::shared_ptr<sinsp_threadinfo>& child) {
		for(auto it = m_children.begin(); it != m_children.end(); ++it) {
			auto locked = it->lock();
			if(locked.get() == child.get()) {
				m_children.erase(it);
				if(m_not_expired_children > 0) {
					m_not_expired_children--;
				}
				return;
			}
		}
	}

	inline void clean_expired_children_unlocked() {
		auto child = m_children.begin();
		while(child != m_children.end()) {
			if(child->expired()) {
				child = m_children.erase(child);
				continue;
			}
			child++;
		}
	}

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

	// Mutex protecting exec-info group (strings, vectors, and related fields)
	mutable std::shared_mutex m_state_mutex;

	// Atomic identity fields
	int64_t m_pid;
	int64_t m_ptid;
	int64_t m_reaper_tid;
	int64_t m_sid;
	int64_t m_vtid;
	int64_t m_vpid;
	int64_t m_vpgid;
	int64_t m_pgid;

	// Atomic flags/credentials/stats
	uint32_t m_flags;
	int64_t m_fdlimit;
	uint32_t m_uid;
	uint32_t m_gid;
	uint32_t m_loginuid;
	uint64_t m_cap_permitted;
	uint64_t m_cap_effective;
	uint64_t m_cap_inheritable;
	uint32_t m_vmsize_kb;
	uint32_t m_vmrss_kb;
	uint32_t m_vmswap_kb;
	uint64_t m_pfmajor;
	uint64_t m_pfminor;
	uint32_t m_tty;
	bool m_filtered_out;

	// Mutex-protected exec-info group (guarded by m_state_mutex)
	std::string m_comm;
	std::string m_exe;
	std::string m_exepath;
	bool m_exe_writable;
	bool m_exe_upper_layer;
	bool m_exe_lower_layer;
	bool m_exe_from_memfd;
	uint64_t m_exe_ino;
	uint64_t m_exe_ino_ctime;
	uint64_t m_exe_ino_mtime;
	uint64_t m_exe_ino_ctime_duration_clone_ts;
	uint64_t m_exe_ino_ctime_duration_pidns_start;
	std::string m_root;
	std::string m_cmd_line;
	std::vector<std::string> m_args;
	std::vector<std::string> m_env;
	cgroups_t m_cgroups;
	uint64_t m_lastexec_ts{0};

	// Thread group info (synchronized via std::atomic_load/store)
	std::shared_ptr<thread_group_info> m_tginfo;

	// Children (synchronized via m_children_mutex)
	mutable std::mutex m_children_mutex;
	std::list<std::weak_ptr<sinsp_threadinfo>> m_children;
	uint64_t m_not_expired_children;

	// Internal state
	sinsp_fdtable m_fdtable;
	const libsinsp::state::base_table* m_main_fdtable;
	std::string m_cwd;
	uint8_t* m_lastevent_data;

	// Multi-event processing state (synchronized via relaxed atomics in getters/setters)
	int64_t m_lastevent_fd;
	uint64_t m_lastevent_ts;
	uint64_t m_prevevent_ts;
	uint64_t m_lastaccess_ts;
	uint64_t m_clone_ts;
	uint16_t m_lastevent_type;
	uint16_t m_lastevent_cpuid;
	sinsp_evt::category m_lastevent_category;
	bool m_parent_loop_detected;

	// State framework table adapters (must come after m_args, m_env, m_cgroups)
	libsinsp::state::stl_container_table_adapter<decltype(m_args)> m_args_table_adapter;
	libsinsp::state::stl_container_table_adapter<decltype(m_env)> m_env_table_adapter;
	libsinsp::state::stl_container_table_adapter<
	        decltype(m_cgroups),
	        libsinsp::state::pair_table_entry_adapter<std::string, std::string>>
	        m_cgroups_table_adapter;
};

/*@}*/

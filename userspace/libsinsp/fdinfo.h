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

#include <libscap/scap.h>
#include <libsinsp/tuples.h>
#include <libsinsp/sinsp_public.h>
#include <libsinsp/state/table.h>
#include <libsinsp/sync_policy.h>

#include <unordered_map>
#include <memory>
#include <libsinsp/packed_data.h>

// fd type characters
#define CHAR_FD_FILE 'f'
#define CHAR_FD_IPV4_SOCK '4'
#define CHAR_FD_IPV6_SOCK '6'
#define CHAR_FD_DIRECTORY 'd'
#define CHAR_FD_IPV4_SERVSOCK '4'
#define CHAR_FD_IPV6_SERVSOCK '6'
#define CHAR_FD_FIFO 'p'
#define CHAR_FD_UNIX_SOCK 'u'
#define CHAR_FD_EVENT 'e'
#define CHAR_FD_UNKNOWN 'o'
#define CHAR_FD_UNSUPPORTED 'X'
#define CHAR_FD_SIGNAL 's'
#define CHAR_FD_EVENTPOLL 'l'
#define CHAR_FD_INOTIFY 'i'
#define CHAR_FD_TIMERFD 't'
#define CHAR_FD_NETLINK 'n'
#define CHAR_FD_BPF 'b'
#define CHAR_FD_USERFAULTFD 'u'
#define CHAR_FD_IO_URING 'r'
#define CHAR_FD_MEMFD 'm'
#define CHAR_FD_PIDFD 'P'

template<typename SyncPolicy>
class sinsp_threadinfo_impl;
using sinsp_threadinfo = sinsp_threadinfo_impl<sync_policy_default>;

/** @defgroup state State management
 * A collection of classes to query process and FD state.
 *  @{
 */

union sinsp_sockinfo {
	ipv4tuple m_ipv4info;             ///< The tuple if this an IPv4 socket.
	ipv6tuple m_ipv6info;             ///< The tuple if this an IPv6 socket.
	ipv4serverinfo m_ipv4serverinfo;  ///< Information about an IPv4 server socket.
	ipv6serverinfo m_ipv6serverinfo;  ///< Information about an IPv6 server socket.
	unix_tuple m_unixinfo;            ///< The tuple if this a unix socket.
};

/*!
  \brief File Descriptor information class.
  This class contains the full state for a FD, and a bunch of functions to
  manipulate FDs and retrieve FD information.

  \note As a library user, you won't need to construct thread objects. Rather,
   you get them by calling \ref sinsp_evt::get_fd_info or
   \ref sinsp_threadinfo::get_fd.
*/
template<typename SyncPolicy = sync_policy_default>
class SINSP_PUBLIC sinsp_fdinfo_impl : public libsinsp::state::extensible_struct {
public:
	using traits = libsinsp::sync_policy_traits<SyncPolicy>;
	using inner_mutex_type = typename traits::fdinfo_inner_mutex;

	/*!
	  \brief FD flags.
	*/
	enum flags {
		FLAGS_NONE = 0,
		FLAGS_FROM_PROC = (1 << 0),
		// FLAGS_TRANSACTION = (1 << 1), // note: deprecated
		FLAGS_ROLE_CLIENT = (1 << 2),
		FLAGS_ROLE_SERVER = (1 << 3),
		// FLAGS_CLOSE_IN_PROGRESS = (1 << 4), // note: deprecated
		// FLAGS_CLOSE_CANCELED = (1 << 5), // note: deprecated
		FLAGS_IS_SOCKET_PIPE = (1 << 6),
		// FLAGS_IS_TRACER_FILE = (1 << 7), // note: deprecated
		// FLAGS_IS_TRACER_FD = (1 << 8), // note: deprecated
		// FLAGS_IS_NOT_TRACER_FD = (1 << 9), // note: deprecated
		FLAGS_IN_BASELINE_R = (1 << 10),
		FLAGS_IN_BASELINE_RW = (1 << 11),
		FLAGS_IN_BASELINE_OTHER = (1 << 12),
		FLAGS_SOCKET_CONNECTED = (1 << 13),
		FLAGS_IS_CLONED = (1 << 14),
		FLAGS_CONNECTION_PENDING = (1 << 15),
		FLAGS_CONNECTION_FAILED = (1 << 16),
		FLAGS_OVERLAY_UPPER = (1 << 17),
		FLAGS_OVERLAY_LOWER = (1 << 18),
	};

	sinsp_fdinfo_impl(
	        const std::shared_ptr<libsinsp::state::dynamic_field_infos>& dyn_fields = nullptr);
	sinsp_fdinfo_impl(sinsp_fdinfo_impl&& o) = default;
	sinsp_fdinfo_impl& operator=(sinsp_fdinfo_impl&& o) = default;
	sinsp_fdinfo_impl(const sinsp_fdinfo_impl& o) = default;
	sinsp_fdinfo_impl& operator=(const sinsp_fdinfo_impl& o) = default;

	virtual ~sinsp_fdinfo_impl() = default;

	virtual std::unique_ptr<sinsp_fdinfo_impl> clone() const {
		std::shared_lock lock(m_mutex.m);
		return std::make_unique<sinsp_fdinfo_impl>(*this);
	}

	inline std::unique_lock<inner_mutex_type> exclusive_lock() const {
		return std::unique_lock(m_mutex.m);
	}

	inline void snapshot_oldname() {
		std::unique_lock lock(m_mutex.m);
		m_oldname = m_name;
	}

	// --- Thread-safe getters (return by value, shared_lock) ---
	inline scap_fd_type get_type() const {
		std::shared_lock l(m_mutex.m);
		return m_type;
	}
	inline uint32_t get_openflags() const {
		std::shared_lock l(m_mutex.m);
		return m_openflags;
	}
	inline std::string get_name() const {
		std::shared_lock l(m_mutex.m);
		return m_name;
	}
	inline std::string get_name_raw() const {
		std::shared_lock l(m_mutex.m);
		return m_name_raw;
	}
	inline std::string get_oldname() const {
		std::shared_lock l(m_mutex.m);
		return m_oldname;
	}
	inline uint32_t get_flags_value() const {
		std::shared_lock l(m_mutex.m);
		return m_flags;
	}
	inline sinsp_sockinfo get_sockinfo() const {
		std::shared_lock l(m_mutex.m);
		return m_sockinfo;
	}
	inline uint32_t get_dev() const {
		std::shared_lock l(m_mutex.m);
		return m_dev;
	}
	inline uint32_t get_mount_id() const {
		std::shared_lock l(m_mutex.m);
		return m_mount_id;
	}
	inline int64_t get_fd_num() const {
		std::shared_lock l(m_mutex.m);
		return m_fd;
	}

	// --- Thread-safe setters (unique_lock) ---
	inline void set_type(scap_fd_type t) {
		std::unique_lock l(m_mutex.m);
		m_type = t;
	}
	inline void set_openflags(uint32_t f) {
		std::unique_lock l(m_mutex.m);
		m_openflags = f;
	}
	inline void or_openflags(uint32_t f) {
		std::unique_lock l(m_mutex.m);
		m_openflags |= f;
	}
	inline void and_openflags(uint32_t f) {
		std::unique_lock l(m_mutex.m);
		m_openflags &= f;
	}
	inline void set_name(std::string n) {
		std::unique_lock l(m_mutex.m);
		m_name = std::move(n);
	}
	inline void set_name_raw(std::string n) {
		std::unique_lock l(m_mutex.m);
		m_name_raw = std::move(n);
	}
	inline void set_oldname(std::string n) {
		std::unique_lock l(m_mutex.m);
		m_oldname = std::move(n);
	}
	inline void set_flags_value(uint32_t f) {
		std::unique_lock l(m_mutex.m);
		m_flags = f;
	}
	inline void set_sockinfo(sinsp_sockinfo si) {
		std::unique_lock l(m_mutex.m);
		m_sockinfo = si;
	}
	inline void set_dev(uint32_t d) {
		std::unique_lock l(m_mutex.m);
		m_dev = d;
	}
	inline void set_mount_id(uint32_t m) {
		std::unique_lock l(m_mutex.m);
		m_mount_id = m;
	}
	inline void set_ino(uint64_t i) {
		std::unique_lock l(m_mutex.m);
		m_ino = i;
	}
	inline void set_pid_fd(int64_t p) {
		std::unique_lock l(m_mutex.m);
		m_pid = p;
	}
	inline void set_fd_num(int64_t f) {
		std::unique_lock l(m_mutex.m);
		m_fd = f;
	}

	// --- Compound setters (unique_lock, multi-field atomic mutations) ---
	void set_file_info(scap_fd_type type,
	                   uint32_t openflags,
	                   uint32_t mount_id,
	                   uint32_t dev,
	                   uint64_t ino);
	void init_socket(scap_fd_type type, scap_l4_proto l4proto);
	void set_pipe_info(uint64_t ino, uint32_t openflags);
	void set_memfd_info(uint32_t flags);
	void set_pidfd_info(int64_t pid, uint32_t flags);
	void set_cloexec(bool enable);
	void set_unix_socket_info(const uint8_t* packed_data, std::string name);

	// --- Existing query methods (now with shared_lock) ---

	char get_typechar() const;

	const char* get_typestring() const;

	std::string tostring_clean() const;

	inline bool is_syslog() const {
		std::shared_lock l(m_mutex.m);
		return m_name.find("/dev/log") != std::string::npos;
	}

	inline bool is_unix_socket() const {
		std::shared_lock l(m_mutex.m);
		return m_type == SCAP_FD_UNIX_SOCK;
	}

	inline bool is_ipv4_socket() const {
		std::shared_lock l(m_mutex.m);
		return m_type == SCAP_FD_IPV4_SOCK;
	}

	inline bool is_ipv6_socket() const {
		std::shared_lock l(m_mutex.m);
		return m_type == SCAP_FD_IPV6_SOCK;
	}

	inline bool is_udp_socket() const {
		std::shared_lock l(m_mutex.m);
		return m_type == SCAP_FD_IPV4_SOCK &&
		       m_sockinfo.m_ipv4info.m_fields.m_l4proto == SCAP_L4_UDP;
	}

	inline bool is_tcp_socket() const {
		std::shared_lock l(m_mutex.m);
		return m_type == SCAP_FD_IPV4_SOCK &&
		       m_sockinfo.m_ipv4info.m_fields.m_l4proto == SCAP_L4_TCP;
	}

	inline bool is_pipe() const {
		std::shared_lock l(m_mutex.m);
		return m_type == SCAP_FD_FIFO;
	}

	inline bool is_file() const {
		std::shared_lock l(m_mutex.m);
		return m_type == SCAP_FD_FILE || m_type == SCAP_FD_FILE_V2;
	}

	inline bool is_directory() const {
		std::shared_lock l(m_mutex.m);
		return m_type == SCAP_FD_DIRECTORY;
	}

	inline bool is_pidfd() const {
		std::shared_lock l(m_mutex.m);
		return m_type == SCAP_FD_PIDFD;
	}

	inline uint16_t get_serverport() const {
		std::shared_lock l(m_mutex.m);
		if(m_type == SCAP_FD_IPV4_SOCK) {
			return m_sockinfo.m_ipv4info.m_fields.m_dport;
		} else if(m_type == SCAP_FD_IPV6_SOCK) {
			return m_sockinfo.m_ipv6info.m_fields.m_dport;
		} else {
			return 0;
		}
	}

	inline uint32_t get_device() const {
		std::shared_lock l(m_mutex.m);
		return m_dev;
	}

	inline uint32_t get_device_major() const {
		std::shared_lock l(m_mutex.m);
		return (m_dev & 0xfff00) >> 8;
	}

	inline uint32_t get_device_minor() const {
		std::shared_lock l(m_mutex.m);
		return (m_dev & 0xff) | ((m_dev >> 12) & 0xfff00);
	}

	inline uint64_t get_ino() const {
		std::shared_lock l(m_mutex.m);
		return m_ino;
	}

	inline int64_t get_pid() const {
		std::shared_lock l(m_mutex.m);
		return m_pid;
	}

	inline void set_unix_info(const uint8_t* packed_data) {
		std::unique_lock l(m_mutex.m);
		const auto* source = packed::un_socktuple::source(packed_data);
		const auto* dest = packed::un_socktuple::dest(packed_data);
		memcpy(&m_sockinfo.m_unixinfo.m_fields.m_source, source, sizeof(uint64_t));
		memcpy(&m_sockinfo.m_unixinfo.m_fields.m_dest, dest, sizeof(uint64_t));
	}

	scap_l4_proto get_l4proto() const;

	inline bool is_role_server() const {
		std::shared_lock l(m_mutex.m);
		return (m_flags & FLAGS_ROLE_SERVER) == FLAGS_ROLE_SERVER;
	}

	inline bool is_role_client() const {
		std::shared_lock l(m_mutex.m);
		return (m_flags & FLAGS_ROLE_CLIENT) == FLAGS_ROLE_CLIENT;
	}

	inline bool is_role_none() const {
		std::shared_lock l(m_mutex.m);
		return (m_flags & (FLAGS_ROLE_CLIENT | FLAGS_ROLE_SERVER)) == 0;
	}

	inline bool is_socket_connected() const {
		std::shared_lock l(m_mutex.m);
		return (m_flags & FLAGS_SOCKET_CONNECTED) == FLAGS_SOCKET_CONNECTED;
	}

	inline bool is_socket_pending() const {
		std::shared_lock l(m_mutex.m);
		return (m_flags & FLAGS_CONNECTION_PENDING) == FLAGS_CONNECTION_PENDING;
	}

	inline bool is_socket_failed() const {
		std::shared_lock l(m_mutex.m);
		return (m_flags & FLAGS_CONNECTION_FAILED) == FLAGS_CONNECTION_FAILED;
	}

	inline bool is_cloned() const {
		std::shared_lock l(m_mutex.m);
		return (m_flags & FLAGS_IS_CLONED) == FLAGS_IS_CLONED;
	}

	inline bool is_overlay_upper() const {
		std::shared_lock l(m_mutex.m);
		return (m_flags & FLAGS_OVERLAY_UPPER) == FLAGS_OVERLAY_UPPER;
	}

	inline bool is_overlay_lower() const {
		std::shared_lock l(m_mutex.m);
		return (m_flags & FLAGS_OVERLAY_LOWER) == FLAGS_OVERLAY_LOWER;
	}

	void add_filename_raw(std::string_view rawpath);

	void add_filename(std::string_view fullpath);

	inline void set_role_server() {
		std::unique_lock l(m_mutex.m);
		m_flags |= FLAGS_ROLE_SERVER;
	}

	inline void set_role_client() {
		std::unique_lock l(m_mutex.m);
		m_flags |= FLAGS_ROLE_CLIENT;
	}

	void set_net_role_by_guessing(const sinsp_threadinfo& ptinfo, bool incoming);

	inline void reset_flags() {
		std::unique_lock l(m_mutex.m);
		m_flags = FLAGS_NONE;
	}

	inline void set_socketpipe() {
		std::unique_lock l(m_mutex.m);
		m_flags |= FLAGS_IS_SOCKET_PIPE;
	}

	inline bool is_socketpipe() const {
		std::shared_lock l(m_mutex.m);
		return (m_flags & FLAGS_IS_SOCKET_PIPE) == FLAGS_IS_SOCKET_PIPE;
	}

	inline bool has_no_role() const {
		std::shared_lock l(m_mutex.m);
		return !(m_flags & FLAGS_ROLE_CLIENT) && !(m_flags & FLAGS_ROLE_SERVER);
	}

	inline void set_inpipeline_r() {
		std::unique_lock l(m_mutex.m);
		m_flags |= FLAGS_IN_BASELINE_R;
	}

	inline void set_inpipeline_rw() {
		std::unique_lock l(m_mutex.m);
		m_flags |= FLAGS_IN_BASELINE_RW;
	}

	inline void set_inpipeline_other() {
		std::unique_lock l(m_mutex.m);
		m_flags |= FLAGS_IN_BASELINE_OTHER;
	}

	inline void reset_inpipeline() {
		std::unique_lock l(m_mutex.m);
		m_flags &= ~FLAGS_IN_BASELINE_R;
		m_flags &= ~FLAGS_IN_BASELINE_RW;
		m_flags &= ~FLAGS_IN_BASELINE_OTHER;
	}

	inline bool is_inpipeline_r() const {
		std::shared_lock l(m_mutex.m);
		return (m_flags & FLAGS_IN_BASELINE_R) == FLAGS_IN_BASELINE_R;
	}

	inline bool is_inpipeline_rw() const {
		std::shared_lock l(m_mutex.m);
		return (m_flags & FLAGS_IN_BASELINE_RW) == FLAGS_IN_BASELINE_RW;
	}

	inline bool is_inpipeline_other() const {
		std::shared_lock l(m_mutex.m);
		return (m_flags & FLAGS_IN_BASELINE_OTHER) == FLAGS_IN_BASELINE_OTHER;
	}

	inline void set_socket_connected() {
		std::unique_lock l(m_mutex.m);
		m_flags &= ~(FLAGS_CONNECTION_PENDING | FLAGS_CONNECTION_FAILED);
		m_flags |= FLAGS_SOCKET_CONNECTED;
	}

	inline void set_socket_pending() {
		std::unique_lock l(m_mutex.m);
		m_flags &= ~(FLAGS_SOCKET_CONNECTED | FLAGS_CONNECTION_FAILED);
		m_flags |= FLAGS_CONNECTION_PENDING;
	}

	inline void set_socket_failed() {
		std::unique_lock l(m_mutex.m);
		m_flags &= ~(FLAGS_SOCKET_CONNECTED | FLAGS_CONNECTION_PENDING);
		m_flags |= FLAGS_CONNECTION_FAILED;
	}

	inline void set_is_cloned() {
		std::unique_lock l(m_mutex.m);
		m_flags |= FLAGS_IS_CLONED;
	}

	inline void set_overlay_upper() {
		std::unique_lock l(m_mutex.m);
		m_flags |= FLAGS_OVERLAY_UPPER;
	}

	inline void set_overlay_lower() {
		std::unique_lock l(m_mutex.m);
		m_flags |= FLAGS_OVERLAY_LOWER;
	}

	/*!
	  \brief A static version of static_fields()
	  \return The group of field infos available.
	 */
	static libsinsp::state::static_field_infos get_static_fields();

	friend class sinsp_parser;
	template<typename>
	friend class sinsp_fdtable_impl;
	template<typename>
	friend class sinsp_threadinfo_impl;
	template<typename>
	friend class sinsp_thread_manager_impl;
	friend class sinsp_network_interfaces;

private:
	scap_fd_type m_type = SCAP_FD_UNINITIALIZED;
	uint32_t m_openflags = 0;
	sinsp_sockinfo m_sockinfo = {};
	std::string m_name;
	std::string m_name_raw;
	std::string m_oldname;
	uint32_t m_flags = FLAGS_NONE;
	uint32_t m_dev = 0;
	uint32_t m_mount_id = 0;
	uint64_t m_ino = 0;
	int64_t m_pid = 0;
	int64_t m_fd = -1;

public:
	// Per-fdinfo mutex for thread-safe access. Mutable so const methods can lock.
	// Wrapped in a struct with no-op copy/move so default copy/move constructors
	// and assignments of sinsp_fdinfo work (each copy gets a fresh mutex).
	mutable libsinsp::sinsp_copyable_mutex<inner_mutex_type> m_mutex;
};

using sinsp_fdinfo = sinsp_fdinfo_impl<>;

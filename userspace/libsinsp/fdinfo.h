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
#include <libsinsp/atomic_helpers.h>

#include <unordered_map>
#include <memory>
#include <atomic>
#include <libsinsp/packed_data.h>

// std::atomic<bool> is not copyable, but sinsp_fdinfo_impl needs defaulted
// copy/move. This wrapper loads/stores with relaxed ordering on copy so the
// rest of the class can stay = default.
struct copyable_atomic_flag {
	std::atomic<bool> v{false};

	copyable_atomic_flag() = default;
	explicit copyable_atomic_flag(bool b): v(b) {}
	copyable_atomic_flag(const copyable_atomic_flag& o): v(o.v.load(std::memory_order_relaxed)) {}
	copyable_atomic_flag& operator=(const copyable_atomic_flag& o) {
		v.store(o.v.load(std::memory_order_relaxed), std::memory_order_relaxed);
		return *this;
	}
	copyable_atomic_flag(copyable_atomic_flag&& o) noexcept:
	        v(o.v.load(std::memory_order_relaxed)) {}
	copyable_atomic_flag& operator=(copyable_atomic_flag&& o) noexcept {
		v.store(o.v.load(std::memory_order_relaxed), std::memory_order_relaxed);
		return *this;
	}

	void store(bool b, std::memory_order mo = std::memory_order_seq_cst) { v.store(b, mo); }
	bool load(std::memory_order mo = std::memory_order_seq_cst) const { return v.load(mo); }
	bool exchange(bool b, std::memory_order mo = std::memory_order_seq_cst) {
		return v.exchange(b, mo);
	}
};

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
	using seqlock_type = typename traits::fdinfo_seqlock;
	using write_guard_type = typename traits::fdinfo_seqlock_write_guard;

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
		auto c = std::make_unique<sinsp_fdinfo_impl>();
		static_cast<libsinsp::state::extensible_struct&>(*c) =
		        static_cast<const libsinsp::state::extensible_struct&>(*this);
		m_seq.read([&] {
			c->m_type = m_type;
			c->m_sockinfo = m_sockinfo;
			c->m_openflags = m_openflags;
			c->m_flags = m_flags;
			c->m_dev = m_dev;
			c->m_mount_id = m_mount_id;
			c->m_ino = m_ino;
			c->m_pid = m_pid;
			c->m_fd = m_fd;
			c->m_name = std::atomic_load(&m_name);
			c->m_name_raw = std::atomic_load(&m_name_raw);
			c->m_oldname = std::atomic_load(&m_oldname);
		});
		c->m_name_changed = m_name_changed;
		return c;
	}

	inline write_guard_type write_guard() const { return write_guard_type(m_seq); }

	inline void snapshot_oldname() {
		write_guard_type g(m_seq);
		std::atomic_store(&m_oldname, std::atomic_load(&m_name));
	}

	inline bool consume_name_changed() {
		return m_name_changed.exchange(false, std::memory_order_relaxed);
	}

	// =====================================================================
	// Scalar getters -- lock-free via load_relaxed
	// =====================================================================

	inline scap_fd_type get_type() const { return load_relaxed(m_type); }
	inline uint32_t get_openflags() const { return load_relaxed(m_openflags); }
	inline uint32_t get_flags_value() const { return load_relaxed(m_flags); }
	inline uint32_t get_dev() const { return load_relaxed(m_dev); }
	inline uint32_t get_mount_id() const { return load_relaxed(m_mount_id); }
	inline uint64_t get_ino() const { return load_relaxed(m_ino); }
	inline int64_t get_pid() const { return load_relaxed(m_pid); }
	inline int64_t get_fd_num() const { return load_relaxed(m_fd); }

	inline uint32_t get_device() const { return load_relaxed(m_dev); }
	inline uint32_t get_device_major() const { return (load_relaxed(m_dev) & 0xfff00) >> 8; }
	inline uint32_t get_device_minor() const {
		auto d = load_relaxed(m_dev);
		return (d & 0xff) | ((d >> 12) & 0xfff00);
	}

	// =====================================================================
	// COW string getters -- lock-free via atomic_load
	// =====================================================================

	inline std::string get_name() const {
		auto p = std::atomic_load(&m_name);
		return p ? *p : std::string{};
	}
	inline std::string get_name_raw() const {
		auto p = std::atomic_load(&m_name_raw);
		return p ? *p : std::string{};
	}
	inline std::string get_oldname() const {
		auto p = std::atomic_load(&m_oldname);
		return p ? *p : std::string{};
	}

	// =====================================================================
	// Seqlock-consistent getters (type + sockinfo)
	// =====================================================================

	inline sinsp_sockinfo get_sockinfo() const {
		sinsp_sockinfo si;
		m_seq.read([&] { si = m_sockinfo; });
		return si;
	}

	// =====================================================================
	// Scalar setters -- RAII write guard + relaxed atomic store
	// =====================================================================

	inline void set_type(scap_fd_type t) {
		write_guard_type g(m_seq);
		m_type = t;
	}
	inline void set_openflags(uint32_t f) {
		write_guard_type g(m_seq);
		m_openflags = f;
	}
	inline void or_openflags(uint32_t f) {
		write_guard_type g(m_seq);
		fetch_or_relaxed(m_openflags, f);
	}
	inline void and_openflags(uint32_t f) {
		write_guard_type g(m_seq);
		fetch_and_relaxed(m_openflags, f);
	}
	inline void set_flags_value(uint32_t f) {
		write_guard_type g(m_seq);
		m_flags = f;
	}
	inline void set_dev(uint32_t d) {
		write_guard_type g(m_seq);
		m_dev = d;
	}
	inline void set_mount_id(uint32_t m) {
		write_guard_type g(m_seq);
		m_mount_id = m;
	}
	inline void set_ino(uint64_t i) {
		write_guard_type g(m_seq);
		m_ino = i;
	}
	inline void set_pid_fd(int64_t p) {
		write_guard_type g(m_seq);
		m_pid = p;
	}
	inline void set_fd_num(int64_t f) {
		write_guard_type g(m_seq);
		m_fd = f;
	}
	inline void set_sockinfo(sinsp_sockinfo si) {
		write_guard_type g(m_seq);
		m_sockinfo = si;
	}

	// =====================================================================
	// COW string setters -- RAII write guard + atomic_store
	// =====================================================================

	inline void set_name(std::string n) {
		auto new_ptr = std::make_shared<const std::string>(std::move(n));
		write_guard_type g(m_seq);
		set_name_inner(std::move(new_ptr));
	}

	inline void set_name_inner(std::string n) {
		set_name_inner(std::make_shared<const std::string>(std::move(n)));
	}

	inline void set_name_inner(std::shared_ptr<const std::string> new_ptr) {
		auto old = std::atomic_load(&m_name);
		if(!old || *old != *new_ptr) {
			std::atomic_store(&m_name, std::move(new_ptr));
			m_name_changed.store(true, std::memory_order_relaxed);
		}
	}

	inline void set_name_raw(std::string n) {
		auto new_ptr = std::make_shared<const std::string>(std::move(n));
		write_guard_type g(m_seq);
		std::atomic_store(&m_name_raw, std::move(new_ptr));
	}
	inline void set_oldname(std::string n) {
		auto new_ptr = std::make_shared<const std::string>(std::move(n));
		write_guard_type g(m_seq);
		std::atomic_store(&m_oldname, std::move(new_ptr));
	}

	// =====================================================================
	// Compound setters (defined in fdinfo.cpp; multi-field mutations under write_guard)
	// =====================================================================

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

	// =====================================================================
	// Query methods
	// =====================================================================

	char get_typechar() const;
	const char* get_typestring() const;
	std::string tostring_clean() const;

	inline bool is_syslog() const {
		auto p = std::atomic_load(&m_name);
		return p && p->find("/dev/log") != std::string::npos;
	}

	inline bool is_unix_socket() const { return load_relaxed(m_type) == SCAP_FD_UNIX_SOCK; }
	inline bool is_ipv4_socket() const { return load_relaxed(m_type) == SCAP_FD_IPV4_SOCK; }
	inline bool is_ipv6_socket() const { return load_relaxed(m_type) == SCAP_FD_IPV6_SOCK; }
	inline bool is_pipe() const { return load_relaxed(m_type) == SCAP_FD_FIFO; }
	inline bool is_file() const {
		auto t = load_relaxed(m_type);
		return t == SCAP_FD_FILE || t == SCAP_FD_FILE_V2;
	}
	inline bool is_directory() const { return load_relaxed(m_type) == SCAP_FD_DIRECTORY; }
	inline bool is_pidfd() const { return load_relaxed(m_type) == SCAP_FD_PIDFD; }

	inline bool is_udp_socket() const {
		scap_fd_type t;
		sinsp_sockinfo si;
		m_seq.read([&] {
			t = m_type;
			si = m_sockinfo;
		});
		return t == SCAP_FD_IPV4_SOCK && si.m_ipv4info.m_fields.m_l4proto == SCAP_L4_UDP;
	}

	inline bool is_tcp_socket() const {
		scap_fd_type t;
		sinsp_sockinfo si;
		m_seq.read([&] {
			t = m_type;
			si = m_sockinfo;
		});
		return t == SCAP_FD_IPV4_SOCK && si.m_ipv4info.m_fields.m_l4proto == SCAP_L4_TCP;
	}

	inline uint16_t get_serverport() const {
		scap_fd_type t;
		sinsp_sockinfo si;
		m_seq.read([&] {
			t = m_type;
			si = m_sockinfo;
		});
		if(t == SCAP_FD_IPV4_SOCK) {
			return si.m_ipv4info.m_fields.m_dport;
		} else if(t == SCAP_FD_IPV6_SOCK) {
			return si.m_ipv6info.m_fields.m_dport;
		}
		return 0;
	}

	scap_l4_proto get_l4proto() const;

	inline void set_unix_info(const uint8_t* packed_data) {
		write_guard_type g(m_seq);
		const auto* source = packed::un_socktuple::source(packed_data);
		const auto* dest = packed::un_socktuple::dest(packed_data);
		memcpy(&m_sockinfo.m_unixinfo.m_fields.m_source, source, sizeof(uint64_t));
		memcpy(&m_sockinfo.m_unixinfo.m_fields.m_dest, dest, sizeof(uint64_t));
	}

	// =====================================================================
	// Flag query methods -- lock-free via load_relaxed
	// =====================================================================

	inline bool is_role_server() const {
		return (load_relaxed(m_flags) & FLAGS_ROLE_SERVER) == FLAGS_ROLE_SERVER;
	}
	inline bool is_role_client() const {
		return (load_relaxed(m_flags) & FLAGS_ROLE_CLIENT) == FLAGS_ROLE_CLIENT;
	}
	inline bool is_role_none() const {
		return (load_relaxed(m_flags) & (FLAGS_ROLE_CLIENT | FLAGS_ROLE_SERVER)) == 0;
	}
	inline bool is_socket_connected() const {
		return (load_relaxed(m_flags) & FLAGS_SOCKET_CONNECTED) == FLAGS_SOCKET_CONNECTED;
	}
	inline bool is_socket_pending() const {
		return (load_relaxed(m_flags) & FLAGS_CONNECTION_PENDING) == FLAGS_CONNECTION_PENDING;
	}
	inline bool is_socket_failed() const {
		return (load_relaxed(m_flags) & FLAGS_CONNECTION_FAILED) == FLAGS_CONNECTION_FAILED;
	}
	inline bool is_cloned() const {
		return (load_relaxed(m_flags) & FLAGS_IS_CLONED) == FLAGS_IS_CLONED;
	}
	inline bool is_overlay_upper() const {
		return (load_relaxed(m_flags) & FLAGS_OVERLAY_UPPER) == FLAGS_OVERLAY_UPPER;
	}
	inline bool is_overlay_lower() const {
		return (load_relaxed(m_flags) & FLAGS_OVERLAY_LOWER) == FLAGS_OVERLAY_LOWER;
	}
	inline bool is_socketpipe() const {
		return (load_relaxed(m_flags) & FLAGS_IS_SOCKET_PIPE) == FLAGS_IS_SOCKET_PIPE;
	}
	inline bool has_no_role() const {
		auto f = load_relaxed(m_flags);
		return !(f & FLAGS_ROLE_CLIENT) && !(f & FLAGS_ROLE_SERVER);
	}
	inline bool is_inpipeline_r() const {
		return (load_relaxed(m_flags) & FLAGS_IN_BASELINE_R) == FLAGS_IN_BASELINE_R;
	}
	inline bool is_inpipeline_rw() const {
		return (load_relaxed(m_flags) & FLAGS_IN_BASELINE_RW) == FLAGS_IN_BASELINE_RW;
	}
	inline bool is_inpipeline_other() const {
		return (load_relaxed(m_flags) & FLAGS_IN_BASELINE_OTHER) == FLAGS_IN_BASELINE_OTHER;
	}

	inline bool is_close_on_exec() const {
		auto openflags = load_relaxed(m_openflags);
		if((openflags & PPM_O_CLOEXEC) == PPM_O_CLOEXEC) {
			return true;
		}
		auto type = load_relaxed(m_type);
		if(type == SCAP_FD_EVENTPOLL && (openflags & PPM_EPOLL_CLOEXEC) == PPM_EPOLL_CLOEXEC) {
			return true;
		}
		if(type == SCAP_FD_MEMFD && (openflags & PPM_MFD_CLOEXEC) == PPM_MFD_CLOEXEC) {
			return true;
		}
		return false;
	}

	// =====================================================================
	// Flag setters -- RAII write guard + atomic RMW
	// =====================================================================

	inline void set_role_server() {
		write_guard_type g(m_seq);
		fetch_or_relaxed(m_flags, (uint32_t)FLAGS_ROLE_SERVER);
	}
	inline void set_role_client() {
		write_guard_type g(m_seq);
		fetch_or_relaxed(m_flags, (uint32_t)FLAGS_ROLE_CLIENT);
	}
	inline void reset_flags() {
		write_guard_type g(m_seq);
		store_relaxed(m_flags, (uint32_t)FLAGS_NONE);
	}
	inline void set_socketpipe() {
		write_guard_type g(m_seq);
		fetch_or_relaxed(m_flags, (uint32_t)FLAGS_IS_SOCKET_PIPE);
	}
	inline void set_inpipeline_r() {
		write_guard_type g(m_seq);
		fetch_or_relaxed(m_flags, (uint32_t)FLAGS_IN_BASELINE_R);
	}
	inline void set_inpipeline_rw() {
		write_guard_type g(m_seq);
		fetch_or_relaxed(m_flags, (uint32_t)FLAGS_IN_BASELINE_RW);
	}
	inline void set_inpipeline_other() {
		write_guard_type g(m_seq);
		fetch_or_relaxed(m_flags, (uint32_t)FLAGS_IN_BASELINE_OTHER);
	}
	inline void reset_inpipeline() {
		write_guard_type g(m_seq);
		fetch_and_relaxed(
		        m_flags,
		        ~(uint32_t)(FLAGS_IN_BASELINE_R | FLAGS_IN_BASELINE_RW | FLAGS_IN_BASELINE_OTHER));
	}
	inline void set_socket_connected() {
		constexpr uint32_t target = FLAGS_SOCKET_CONNECTED;
		constexpr uint32_t stale = FLAGS_CONNECTION_PENDING | FLAGS_CONNECTION_FAILED;
		if((load_relaxed(m_flags) & (target | stale)) == target) {
			return;
		}
		write_guard_type g(m_seq);
		fetch_and_relaxed(m_flags, ~stale);
		fetch_or_relaxed(m_flags, target);
	}
	inline void set_socket_pending() {
		write_guard_type g(m_seq);
		fetch_and_relaxed(m_flags, ~(uint32_t)(FLAGS_SOCKET_CONNECTED | FLAGS_CONNECTION_FAILED));
		fetch_or_relaxed(m_flags, (uint32_t)FLAGS_CONNECTION_PENDING);
	}
	inline void set_socket_failed() {
		write_guard_type g(m_seq);
		fetch_and_relaxed(m_flags, ~(uint32_t)(FLAGS_SOCKET_CONNECTED | FLAGS_CONNECTION_PENDING));
		fetch_or_relaxed(m_flags, (uint32_t)FLAGS_CONNECTION_FAILED);
	}
	inline void set_is_cloned() {
		write_guard_type g(m_seq);
		fetch_or_relaxed(m_flags, (uint32_t)FLAGS_IS_CLONED);
	}
	inline void set_overlay_upper() {
		write_guard_type g(m_seq);
		fetch_or_relaxed(m_flags, (uint32_t)FLAGS_OVERLAY_UPPER);
	}
	inline void set_overlay_lower() {
		write_guard_type g(m_seq);
		fetch_or_relaxed(m_flags, (uint32_t)FLAGS_OVERLAY_LOWER);
	}
	inline void clear_close_on_exec_bits() {
		write_guard_type g(m_seq);
		fetch_and_relaxed(m_openflags,
		                  ~(uint32_t)(PPM_O_CLOEXEC | PPM_EPOLL_CLOEXEC | PPM_MFD_CLOEXEC));
	}

	void add_filename_raw(std::string_view rawpath);
	void add_filename(std::string_view fullpath);

	void set_net_role_by_guessing(const sinsp_threadinfo& ptinfo, bool incoming);

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
	// Seqlock-protected group: all writes go through write_guard.
	// Individual reads use load_relaxed (scalars), atomic_load (COW strings),
	// or seqlock read loop (type+sockinfo consistency, clone).
	scap_fd_type m_type = SCAP_FD_UNINITIALIZED;
	uint32_t m_openflags = 0;
	sinsp_sockinfo m_sockinfo = {};
	uint32_t m_flags = FLAGS_NONE;
	uint32_t m_dev = 0;
	uint32_t m_mount_id = 0;
	uint64_t m_ino = 0;
	int64_t m_pid = 0;
	int64_t m_fd = -1;

	// COW strings: reads via std::atomic_load, writes via std::atomic_store.
	std::shared_ptr<const std::string> m_name;
	std::shared_ptr<const std::string> m_name_raw;
	std::shared_ptr<const std::string> m_oldname;

	copyable_atomic_flag m_name_changed;

public:
	// Per-fdinfo seqlock for thread-safe access. Mutable so const methods can
	// synchronize. Copy/move produce a fresh seqlock (see sinsp_seqlock), so
	// default copy/move of sinsp_fdinfo remain valid.
	mutable seqlock_type m_seq;
};

using sinsp_fdinfo = sinsp_fdinfo_impl<>;

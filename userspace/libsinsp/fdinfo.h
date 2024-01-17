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

#include <unordered_map>
#include <vector>
#include <memory>
#include <functional>

#ifdef _WIN32
#define CANCELED_FD_NUMBER INT64_MAX
#else
#define CANCELED_FD_NUMBER std::numeric_limits<int64_t>::max()
#endif

// fd type characters
#define CHAR_FD_FILE			'f'
#define CHAR_FD_IPV4_SOCK		'4'
#define CHAR_FD_IPV6_SOCK		'6'
#define CHAR_FD_DIRECTORY		'd'
#define CHAR_FD_IPV4_SERVSOCK	'4'
#define CHAR_FD_IPV6_SERVSOCK	'6'
#define CHAR_FD_FIFO			'p'
#define CHAR_FD_UNIX_SOCK		'u'
#define CHAR_FD_EVENT			'e'
#define CHAR_FD_UNKNOWN			'o'
#define CHAR_FD_UNSUPPORTED		'X'
#define CHAR_FD_SIGNAL			's'
#define CHAR_FD_EVENTPOLL		'l'
#define CHAR_FD_INOTIFY			'i'
#define CHAR_FD_TIMERFD			't'
#define CHAR_FD_NETLINK			'n'
#define CHAR_FD_BPF     		'b'
#define CHAR_FD_USERFAULTFD		'u'
#define CHAR_FD_IO_URING		'r'
#define CHAR_FD_MEMFD			'm'
#define CHAR_FD_PIDFD			'P'

class sinsp;
class sinsp_threadinfo;
class sinsp_fdinfo;

/** @defgroup state State management
 * A collection of classes to query process and FD state.
 *  @{
 */

union sinsp_sockinfo
{
	ipv4tuple m_ipv4info; ///< The tuple if this an IPv4 socket.
	ipv6tuple m_ipv6info; ///< The tuple if this an IPv6 socket.
	ipv4serverinfo m_ipv4serverinfo;  ///< Information about an IPv4 server socket.
	ipv6serverinfo m_ipv6serverinfo; ///< Information about an IPv6 server socket.
	unix_tuple m_unixinfo; ///< The tuple if this a unix socket.
};

/*!
  \brief File Descriptor information class.
  This class contains the full state for a FD, and a bunch of functions to
  manipulate FDs and retrieve FD information.

  \note As a library user, you won't need to construct thread objects. Rather,
   you get them by calling \ref sinsp_evt::get_fd_info or
   \ref sinsp_threadinfo::get_fd.
*/
class SINSP_PUBLIC sinsp_fdinfo
{
public:
	/*!
	  \brief FD flags.
	*/
	enum flags
	{
		FLAGS_NONE = 0,
		FLAGS_FROM_PROC = (1 << 0),
		//FLAGS_TRANSACTION = (1 << 1), // note: deprecated
		FLAGS_ROLE_CLIENT = (1 << 2),
		FLAGS_ROLE_SERVER = (1 << 3),
		FLAGS_CLOSE_IN_PROGRESS = (1 << 4),
		FLAGS_CLOSE_CANCELED = (1 << 5),
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
	};

	sinsp_fdinfo() = default;
	sinsp_fdinfo(sinsp_fdinfo&& o) = default;
	sinsp_fdinfo& operator=(sinsp_fdinfo&& o) = default;
	sinsp_fdinfo(const sinsp_fdinfo& o) = default;
	sinsp_fdinfo& operator=(const sinsp_fdinfo& o) = default;

	virtual ~sinsp_fdinfo() = default;

	virtual std::unique_ptr<sinsp_fdinfo> clone() const
	{
		auto ret = std::make_unique<sinsp_fdinfo>();
		*(ret.get()) = *this;
		return ret;
	}

	/*!
	  \brief Return a single ASCII character that identifies the FD type.

	  Refer to the CHAR_FD_* defines in this fdinfo.h.
	*/
	char get_typechar() const;

	/*!
	  \brief Return an ASCII string that identifies the FD type.

	  Can be on of 'file', 'directory', ipv4', 'ipv6', 'unix', 'pipe', 'event', 'signalfd', 'eventpoll', 'inotify', 'signalfd'.
	*/
	const char* get_typestring() const;

	/*!
	  \brief Return the fd name, after removing unprintable or invalid characters from it.
	*/
	std::string tostring_clean() const;

	/*!
	  \brief Return true if this is a log device.
	*/
	inline bool is_syslog() const
	{
		return m_name.find("/dev/log") != std::string::npos;
	}

	/*!
	  \brief Returns true if this is a unix socket.
	*/
	inline bool is_unix_socket() const
	{
		return m_type == SCAP_FD_UNIX_SOCK;
	}

	/*!
	  \brief Returns true if this is an IPv4 socket.
	*/
	inline bool is_ipv4_socket() const
	{
		return m_type == SCAP_FD_IPV4_SOCK;
	}

	/*!
	  \brief Returns true if this is an IPv4 socket.
	*/
	inline bool is_ipv6_socket() const
	{
		return m_type == SCAP_FD_IPV6_SOCK;
	}

	/*!
	  \brief Returns true if this is a UDP socket.
	*/
	inline bool is_udp_socket() const
	{
		return m_type == SCAP_FD_IPV4_SOCK && m_sockinfo.m_ipv4info.m_fields.m_l4proto == SCAP_L4_UDP;
	}

	/*!
	  \brief Returns true if this is a unix TCP.
	*/
	inline bool is_tcp_socket() const
	{
		return m_type == SCAP_FD_IPV4_SOCK && m_sockinfo.m_ipv4info.m_fields.m_l4proto == SCAP_L4_TCP;
	}

	/*!
	  \brief Returns true if this is a pipe.
	*/
	inline bool is_pipe() const
	{
		return m_type == SCAP_FD_FIFO;
	}

	/*!
	  \brief Returns true if this is a file.
	*/
	inline bool is_file() const
	{
		return m_type == SCAP_FD_FILE || m_type == SCAP_FD_FILE_V2;
	}

	/*!
	  \brief Returns true if this is a directory.
	*/
	inline bool is_directory() const
	{
		return m_type == SCAP_FD_DIRECTORY;
	}

	/*!
	  \brief Returns true if this is a pidfd, created through pidfd_open.
	*/
	inline bool is_pidfd() const
	{
		return m_type == SCAP_FD_PIDFD;
	}

	inline uint16_t get_serverport() const
	{
		if(m_type == SCAP_FD_IPV4_SOCK)
		{
			return m_sockinfo.m_ipv4info.m_fields.m_dport;
		}
		else if(m_type == SCAP_FD_IPV6_SOCK)
		{
			return m_sockinfo.m_ipv6info.m_fields.m_dport;
		}
		else
		{
			return 0;
		}
	}

	inline uint32_t get_device() const
	{
		return m_dev;
	}

	// see new_encode_dev in include/linux/kdev_t.h
	inline uint32_t get_device_major() const
	{
		return (m_dev & 0xfff00) >> 8;
	}

	// see new_encode_dev in include/linux/kdev_t.h
	inline uint32_t get_device_minor() const
	{
		return (m_dev & 0xff) | ((m_dev >> 12) & 0xfff00);
	}

	inline uint64_t get_ino() const
	{
		return m_ino;
	}

	inline int64_t get_pid() const
	{
		return m_pid;
	}

	inline void set_unix_info(uint8_t* packed_data)
	{
		m_sockinfo.m_unixinfo.m_fields.m_source = *(uint64_t *)(packed_data + 1);
		m_sockinfo.m_unixinfo.m_fields.m_dest = *(uint64_t *)(packed_data + 9);
	}

	/*!
	  \brief If this is a socket, returns the IP protocol. Otherwise, return SCAP_FD_UNKNOWN.
	*/
	scap_l4_proto get_l4proto() const;

	/*!
	  \brief Return true if this FD is a socket server
	*/
	inline bool is_role_server() const
	{
		return (m_flags & FLAGS_ROLE_SERVER) == FLAGS_ROLE_SERVER;
	}

	/*!
	  \brief Return true if this FD is a socket client
	*/
	inline bool is_role_client() const
	{
		return (m_flags & FLAGS_ROLE_CLIENT) == FLAGS_ROLE_CLIENT;
	}

	/*!
	  \brief Return true if this FD is neither a client nor a server
	*/
	inline bool is_role_none() const
	{
		return (m_flags & (FLAGS_ROLE_CLIENT | FLAGS_ROLE_SERVER)) == 0;
	}

	inline bool is_socket_connected() const
	{
		return (m_flags & FLAGS_SOCKET_CONNECTED) == FLAGS_SOCKET_CONNECTED;
	}

	inline bool is_socket_pending() const
	{
		return (m_flags & FLAGS_CONNECTION_PENDING) == FLAGS_CONNECTION_PENDING;
	}

	inline bool is_socket_failed() const
	{
		return (m_flags & FLAGS_CONNECTION_FAILED) == FLAGS_CONNECTION_FAILED;
	}

	inline bool is_cloned() const
	{
		return (m_flags & FLAGS_IS_CLONED) == FLAGS_IS_CLONED;
	}

	void add_filename_raw(std::string_view rawpath);

	void add_filename(std::string_view fullpath);

	inline void set_role_server()
	{
		m_flags |= FLAGS_ROLE_SERVER;
	}

	inline void set_role_client()
	{
		m_flags |= FLAGS_ROLE_CLIENT;
	}

	bool set_net_role_by_guessing(sinsp* inspector,
		sinsp_threadinfo* ptinfo,
		sinsp_fdinfo* pfdinfo,
		bool incoming);

	inline void reset_flags()
	{
		m_flags = FLAGS_NONE;
	}

	inline void set_socketpipe()
	{
		m_flags |= FLAGS_IS_SOCKET_PIPE;
	}

	inline bool is_socketpipe() const
	{
		return (m_flags & FLAGS_IS_SOCKET_PIPE) == FLAGS_IS_SOCKET_PIPE;
	}

	inline bool has_no_role() const
	{
		return !is_role_client() && !is_role_server();
	}

	inline void set_inpipeline_r()
	{
		m_flags |= FLAGS_IN_BASELINE_R;
	}

	inline void set_inpipeline_rw()
	{
		m_flags |= FLAGS_IN_BASELINE_RW;
	}

	inline void set_inpipeline_other()
	{
		m_flags |= FLAGS_IN_BASELINE_OTHER;
	}

	inline void reset_inpipeline()
	{
		m_flags &= ~FLAGS_IN_BASELINE_R;
		m_flags &= ~FLAGS_IN_BASELINE_RW;
		m_flags &= ~FLAGS_IN_BASELINE_OTHER;
	}

	inline bool is_inpipeline_r() const
	{
		return (m_flags & FLAGS_IN_BASELINE_R) == FLAGS_IN_BASELINE_R;
	}

	inline bool is_inpipeline_rw() const
	{
		return (m_flags & FLAGS_IN_BASELINE_RW) == FLAGS_IN_BASELINE_RW;
	}

	inline bool is_inpipeline_other() const
	{
		return (m_flags & FLAGS_IN_BASELINE_OTHER) == FLAGS_IN_BASELINE_OTHER;
	}

	inline void set_socket_connected()
	{
		m_flags &= ~(FLAGS_CONNECTION_PENDING | FLAGS_CONNECTION_FAILED);
		m_flags |= FLAGS_SOCKET_CONNECTED;
	}

	inline void set_socket_pending()
	{
		m_flags &= ~(FLAGS_SOCKET_CONNECTED | FLAGS_CONNECTION_FAILED);
		m_flags |= FLAGS_CONNECTION_PENDING;
	}

	inline void set_socket_failed()
	{
		m_flags &= ~(FLAGS_SOCKET_CONNECTED | FLAGS_CONNECTION_PENDING);
		m_flags |= FLAGS_CONNECTION_FAILED;
	}

	inline void set_is_cloned()
	{
		m_flags |= FLAGS_IS_CLONED;
	}

	scap_fd_type m_type = SCAP_FD_UNINITIALIZED; ///< The fd type, e.g. file, directory, IPv4 socket...
	uint32_t m_openflags = 0; ///< If this FD is a file, the flags that were used when opening it. See the PPM_O_* definitions in driver/ppm_events_public.h.
	sinsp_sockinfo m_sockinfo = {}; ///< Socket-specific state. This is uninitialized (zero) for non-socket FDs.
	std::string m_name; ///< Human readable rendering of this FD. For files, this is the full file name. For sockets, this is the tuple. And so on.
	std::string m_name_raw; // Human readable rendering of this FD. See m_name, only used if fd is a file path. Path is kept "raw" with limited sanitization and without absolute path derivation.
	std::string m_oldname; // The name of this fd at the beginning of event parsing. Used to detect name changes that result from parsing an event.
	uint32_t m_flags = FLAGS_NONE;
	uint32_t m_dev = 0;
	uint32_t m_mount_id = 0;
	uint64_t m_ino = 0;
	int64_t m_pid = 0; // only if fd is a pidfd
};

/*@}*/

///////////////////////////////////////////////////////////////////////////////
// fd info table
///////////////////////////////////////////////////////////////////////////////
class sinsp_fdtable
{
public:
	typedef std::function<bool(int64_t, sinsp_fdinfo&)> fdtable_visitor_t;

	typedef std::function<bool(int64_t, const sinsp_fdinfo&)> fdtable_const_visitor_t;

	sinsp_fdtable(sinsp* inspector);

	inline std::unique_ptr<sinsp_fdinfo> new_fdinfo() const
	{
		return sinsp_fdinfo{}.clone();
	}

	sinsp_fdinfo* find(int64_t fd);
	
	sinsp_fdinfo* add(int64_t fd, std::unique_ptr<sinsp_fdinfo> fdinfo);

	inline bool const_loop(const fdtable_const_visitor_t callback) const
	{
		for(auto it = m_table.begin(); it != m_table.end(); ++it)
		{
			if (!callback(it->first, *(it->second.get())))
			{
				return false;
			}
		}
		return true;
	}

	inline bool loop(const fdtable_visitor_t callback)
	{
		for(auto it = m_table.begin(); it != m_table.end(); ++it)
		{
			if (!callback(it->first, *(it->second.get())))
			{
				return false;
			}
		}
		return true;
	}

	// If the key is present, returns true, otherwise returns false.
	bool erase(int64_t fd);

	void clear();

	size_t size() const;

	void reset_cache();

	inline uint64_t get_tid() const
	{
		return m_tid;
	}

	inline void set_tid(uint64_t v)
	{
		m_tid = v;
	}

private:
	sinsp* m_inspector;
	std::unordered_map<int64_t, std::unique_ptr<sinsp_fdinfo>> m_table;

	//
	// Simple fd cache
	//
	int64_t m_last_accessed_fd;
	sinsp_fdinfo *m_last_accessed_fdinfo;
	uint64_t m_tid;

private:
	void lookup_device(sinsp_fdinfo* fdi, uint64_t fd);
};

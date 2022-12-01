/*
Copyright (C) 2022 The Falco Authors.

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

#include "scap_const.h"
#include "scap_savefile_api.h"

#ifdef __cplusplus
extern "C" {
#endif

/*!
	\mainpage libscap documentation

	\section Introduction

	libscap is the low-level component that exports the following functionality:
	- live capture control (start/stop/pause...)
	- trace file management
	- event retrieval
	- extraction of system state from /proc

	This manual includes the following sections:
	- \ref scap_defs
	- \ref scap_functs
*/

///////////////////////////////////////////////////////////////////////////////
// Public structs and defines
///////////////////////////////////////////////////////////////////////////////

/** @defgroup scap_defs public definitions and structures
 *  @{
 */

//
// Forward declarations
//
typedef struct scap scap_t;
typedef struct ppm_evt_hdr scap_evt;

struct iovec;

//
// Core types
//
#include <time.h>
#include <stdarg.h>
#include "uthash.h"
#include "../common/types.h"
#include "../../driver/ppm_api_version.h"
#include "../../driver/ppm_events_public.h"
#ifdef _WIN32
#include <time.h>
#endif

#include "plugin_info.h"
#include "scap_limits.h"
#include "scap_open.h"
#include "scap_procs.h"
#include "scap_test.h"

/* Include engine-specific params. */
#include <engine/bpf/bpf_public.h>
#include <engine/gvisor/gvisor_public.h>
#include <engine/kmod/kmod_public.h>
#include <engine/modern_bpf/modern_bpf_public.h>
#include <engine/nodriver/nodriver_public.h>
#include <engine/savefile/savefile_public.h>
#include <engine/source_plugin/source_plugin_public.h>
#include <engine/test_input/test_input_public.h>
#include <engine/udig/udig_public.h>

//
// The minimum API and schema versions the driver has to support before we can use it
//
// The reason to increment these would be a bug in the driver that userspace
// cannot or does not want to work around.
//
// Note: adding new events or event fields should not need a version bump
// here, since libscap has to suport old event formats anyway (for capture
// files).
//
// If a consumer relies on events or APIs added in a new version, it should
// call `scap_get_driver_api_version()` and/or `scap_get_driver_schema_version()`
// and handle the result
//
#define SCAP_MINIMUM_DRIVER_API_VERSION PPM_API_VERSION(3, 0, 0)
#define SCAP_MINIMUM_DRIVER_SCHEMA_VERSION PPM_API_VERSION(2, 0, 0)

// 
// This is the dimension we used before introducing the variable buffer size.
//
#define DEFAULT_DRIVER_BUFFER_BYTES_DIM 8 * 1024 * 1024

//
// Value for proc_scan_timeout_ms field in scap_open_args, to specify
// that scan should run to completion without any timeout imposed
//
#define SCAP_PROC_SCAN_TIMEOUT_NONE 0

//
// Value for proc_scan_log_interval_ms field in scap_open_args, to specify
// that no progress logging should be performed
//
#define SCAP_PROC_SCAN_LOG_NONE 0


/*!
  \brief Statistics about an in progress capture
*/
typedef struct scap_stats
{
	uint64_t n_evts; ///< Total number of events that were received by the driver.
	uint64_t n_drops; ///< Number of dropped events.
	uint64_t n_drops_buffer; ///< Number of dropped events caused by full buffer.
	uint64_t n_drops_buffer_clone_fork_enter;
	uint64_t n_drops_buffer_clone_fork_exit;
	uint64_t n_drops_buffer_execve_enter;
	uint64_t n_drops_buffer_execve_exit;
	uint64_t n_drops_buffer_connect_enter;
	uint64_t n_drops_buffer_connect_exit;
	uint64_t n_drops_buffer_open_enter;
	uint64_t n_drops_buffer_open_exit;
	uint64_t n_drops_buffer_dir_file_enter;
	uint64_t n_drops_buffer_dir_file_exit;
	uint64_t n_drops_buffer_other_interest_enter;
	uint64_t n_drops_buffer_other_interest_exit;
	uint64_t n_drops_scratch_map; ///< Number of dropped events caused by full frame scratch map.
	uint64_t n_drops_pf; ///< Number of dropped events caused by invalid memory access.
	uint64_t n_drops_bug; ///< Number of dropped events caused by an invalid condition in the kernel instrumentation.
	uint64_t n_preemptions; ///< Number of preemptions.
	uint64_t n_suppressed; ///< Number of events skipped due to the tid being in a set of suppressed tids.
	uint64_t n_tids_suppressed; ///< Number of threads currently being suppressed.
}scap_stats;

/*!
  \brief Information about the parameter of an event
*/
typedef struct evt_param_info
{
	const char* name; ///< The event name.
	uint32_t type; ///< The event type. See the ppm_event_type enum in driver/ppm_events_public.h
	uint32_t len; ///< The event total length.
	char* val; ///< The event data.
}evt_param_info;

/*!
  \brief File Descriptor type
*/
typedef enum scap_fd_type
{
	SCAP_FD_UNINITIALIZED = -1,
	SCAP_FD_UNKNOWN = 0,
	SCAP_FD_FILE = 1,
	SCAP_FD_DIRECTORY = 2,
	SCAP_FD_IPV4_SOCK = 3,
	SCAP_FD_IPV6_SOCK = 4,
	SCAP_FD_IPV4_SERVSOCK = 5,
	SCAP_FD_IPV6_SERVSOCK = 6,
	SCAP_FD_FIFO = 7,
	SCAP_FD_UNIX_SOCK = 8,
	SCAP_FD_EVENT = 9,
	SCAP_FD_UNSUPPORTED = 10,
	SCAP_FD_SIGNALFD = 11,
	SCAP_FD_EVENTPOLL = 12,
	SCAP_FD_INOTIFY = 13,
	SCAP_FD_TIMERFD = 14,
	SCAP_FD_NETLINK = 15,
	SCAP_FD_FILE_V2 = 16,
	SCAP_FD_BPF = 17,
	SCAP_FD_USERFAULTFD = 18,
	SCAP_FD_IOURING = 19,
}scap_fd_type;

/*!
  \brief Socket type / transport protocol
*/
typedef enum scap_l4_proto
{
	SCAP_L4_UNKNOWN = 0, ///< unknown protocol, likely caused by some parsing problem
	SCAP_L4_NA = 1, ///< protocol not available, because the fd is not a socket
	SCAP_L4_TCP = 2,
	SCAP_L4_UDP = 3,
	SCAP_L4_ICMP = 4,
	SCAP_L4_RAW = 5, ///< Raw socket
}scap_l4_proto;

/*!
  \brief Information about a file descriptor
*/
typedef struct scap_fdinfo
{
	int64_t fd; ///< The FD number, which uniquely identifies this file descriptor.
	uint64_t ino; ///< The inode.
	scap_fd_type type; ///< This file descriptor's type.
	union
	{
		struct
		{
		  uint32_t sip; ///< Source IP
		  uint32_t dip; ///< Destination IP
		  uint16_t sport; ///< Source port
		  uint16_t dport; ///< Destination port
		  uint8_t l4proto; ///< Transport protocol. See \ref scap_l4_proto.
		} ipv4info; ///< Information specific to IPv4 sockets
		struct
		{
			uint32_t sip[4]; ///< Source IP
			uint32_t dip[4]; ///< Destination IP
			uint16_t sport; ///< Source Port
			uint16_t dport; ///< Destination Port
			uint8_t l4proto; ///< Transport protocol. See \ref scap_l4_proto.
		} ipv6info; ///< Information specific to IPv6 sockets
		struct
		{
		  uint32_t ip; ///< Local IP
		  uint16_t port; ///< Local Port
		  uint8_t l4proto; ///< Transport protocol. See \ref scap_l4_proto.
		} ipv4serverinfo; ///< Information specific to IPv4 server sockets, e.g. sockets used for bind().
		struct
		{
			uint32_t ip[4]; ///< Local IP
			uint16_t port; ///< Local Port
			uint8_t l4proto; ///< Transport protocol. See \ref scap_l4_proto.
		} ipv6serverinfo; ///< Information specific to IPv6 server sockets, e.g. sockets used for bind().
		struct
		{
			uint64_t source; ///< Source socket endpoint
		  	uint64_t destination; ///< Destination socket endpoint
			char fname[SCAP_MAX_PATH_SIZE]; ///< Name associated to this unix socket
		} unix_socket_info; ///< Information specific to unix sockets
		struct
		{
			uint32_t open_flags; ///< Flags associated with the file
			char fname[SCAP_MAX_PATH_SIZE]; ///< Name associated to this file
			uint32_t mount_id; ///< The id of the vfs mount the file is in until we find dev major:minor
			uint32_t dev; ///< Major/minor number of the device containing this file
		} regularinfo; ///< Information specific to regular files
		char fname[SCAP_MAX_PATH_SIZE];  ///< The name for file system FDs
	}info;
	UT_hash_handle hh; ///< makes this structure hashable
}scap_fdinfo;

/*!
  \brief Process information
*/
typedef struct scap_threadinfo
{
	uint64_t tid; ///< The thread/task id.
	uint64_t pid; ///< The id of the process containing this thread. In single thread processes, this is equal to tid.
	uint64_t ptid; ///< The id of the thread that created this thread.
	uint64_t sid; ///< The session id of the process containing this thread.
	uint64_t vpgid; ///< The process group of this thread, as seen from its current pid namespace
	char comm[SCAP_MAX_PATH_SIZE+1]; ///< Command name (e.g. "top")
	char exe[SCAP_MAX_PATH_SIZE+1]; ///< argv[0] (e.g. "sshd: user@pts/4")
	char exepath[SCAP_MAX_PATH_SIZE+1]; ///< full executable path
	bool exe_writable; ///< true if the original executable is writable by the same user that spawned it.
	bool exe_upper_layer; //< True if the original executable belongs to upper layer in overlayfs
	char args[SCAP_MAX_ARGS_SIZE+1]; ///< Command line arguments (e.g. "-d1")
	uint16_t args_len; ///< Command line arguments length
	char env[SCAP_MAX_ENV_SIZE+1]; ///< Environment
	uint16_t env_len; ///< Environment length
	char cwd[SCAP_MAX_PATH_SIZE+1]; ///< The current working directory
	int64_t fdlimit; ///< The maximum number of files this thread is allowed to open
	uint32_t flags; ///< the process flags.
	uint32_t uid; ///< user id
	uint32_t gid; ///< group id
	uint64_t cap_permitted; ///< permitted capabilities
	uint64_t cap_effective; ///< effective capabilities
	uint64_t cap_inheritable; ///< inheritable capabilities
	uint64_t exe_ino; ///< executable inode ino
	uint64_t exe_ino_ctime; ///< executable inode ctime (last status change time)
	uint64_t exe_ino_mtime; ///< executable inode mtime (last modification time)
	uint64_t exe_ino_ctime_duration_clone_ts; ///< duration in ns between executable inode ctime (last status change time) and clone_ts
	uint64_t exe_ino_ctime_duration_pidns_start; ///< duration in ns between pidns start ts and executable inode ctime (last status change time) if pidns start predates ctime
	uint32_t vmsize_kb; ///< total virtual memory (as kb)
	uint32_t vmrss_kb; ///< resident non-swapped memory (as kb)
	uint32_t vmswap_kb; ///< swapped memory (as kb)
	uint64_t pfmajor; ///< number of major page faults since start
	uint64_t pfminor; ///< number of minor page faults since start
	int64_t vtid;  ///< The virtual id of this thread.
	int64_t vpid; ///< The virtual id of the process containing this thread. In single thread threads, this is equal to vtid.
	uint64_t pidns_init_start_ts; ///<The pid_namespace init task start_time ts.
	char cgroups[SCAP_MAX_CGROUPS_SIZE];
	uint16_t cgroups_len;
	char root[SCAP_MAX_PATH_SIZE+1];
	int filtered_out; ///< nonzero if this entry should not be saved to file
	scap_fdinfo* fdlist; ///< The fd table for this process
	uint64_t clone_ts; ///< When the clone that started this process happened.
	int32_t tty; ///< Number of controlling terminal
    int32_t loginuid; ///< loginuid (auid)

	UT_hash_handle hh; ///< makes this structure hashable
}scap_threadinfo;

/*!
  \brief Mount information
*/
typedef struct {
	uint64_t mount_id; ///< mount id from /proc/self/mountinfo
	uint32_t dev; ///< device number
	UT_hash_handle hh; ///< makes this structure hashable
} scap_mountinfo;

//
// The following stuff is byte aligned because we save it to disk.
//
#if defined _MSC_VER
#pragma pack(push)
#pragma pack(1)
#elif defined __sun
#pragma pack(1)
#else
#pragma pack(push, 1)
#endif

/*!
  \brief Machine information
*/
typedef struct _scap_machine_info
{
	uint32_t num_cpus;	///< Number of processors
	uint64_t memory_size_bytes; ///< Physical memory size
	uint64_t max_pid; ///< Highest PID number on this machine
	char hostname[128]; ///< The machine hostname
	uint64_t boot_ts_epoch; ///< Host boot ts in nanoseconds (epoch)
	uint64_t reserved2; ///< reserved for future use
	uint64_t reserved3; ///< reserved for future use
	uint64_t reserved4; ///< reserved for future use
}scap_machine_info;


#define SCAP_IPV6_ADDR_LEN 16

/*!
  \brief Interface address type
*/
typedef enum scap_ifinfo_type
{
	SCAP_II_UNKNOWN = 0,
	SCAP_II_IPV4 = 1,
	SCAP_II_IPV6 = 2,
	SCAP_II_IPV4_NOLINKSPEED = 3,
	SCAP_II_IPV6_NOLINKSPEED = 4,
}scap_ifinfo_type;

/*!
  \brief IPv4 interface address information
*/
typedef struct scap_ifinfo_ipv4
{
	// NB: new fields must be appended
	uint16_t type; ///< Interface type
	uint16_t ifnamelen;
	uint32_t addr; ///< Interface address
	uint32_t netmask; ///< Interface netmask
	uint32_t bcast; ///< Interface broadcast address
	uint64_t linkspeed; ///< Interface link speed
	char ifname[SCAP_MAX_PATH_SIZE]; ///< interface name (e.g. "eth0")
}scap_ifinfo_ipv4;

/*!
  \brief For backward compatibility only
*/
typedef struct scap_ifinfo_ipv4_nolinkspeed
{
	uint16_t type;
	uint16_t ifnamelen;
	uint32_t addr;
	uint32_t netmask;
	uint32_t bcast;
	char ifname[SCAP_MAX_PATH_SIZE];
}scap_ifinfo_ipv4_nolinkspeed;

/*!
  \brief IPv6 interface address information
*/
typedef struct scap_ifinfo_ipv6
{
	// NB: new fields must be appended
	uint16_t type;
	uint16_t ifnamelen;
	char addr[SCAP_IPV6_ADDR_LEN]; ///< Interface address
	char netmask[SCAP_IPV6_ADDR_LEN]; ///< Interface netmask
	char bcast[SCAP_IPV6_ADDR_LEN]; ///< Interface broadcast address
	uint64_t linkspeed; ///< Interface link speed
	char ifname[SCAP_MAX_PATH_SIZE]; ///< interface name (e.g. "eth0")
}scap_ifinfo_ipv6;

/*!
  \brief For backword compatibility only
*/
typedef struct scap_ifinfo_ipv6_nolinkspeed
{
	uint16_t type;
	uint16_t ifnamelen;
	char addr[SCAP_IPV6_ADDR_LEN];
	char netmask[SCAP_IPV6_ADDR_LEN];
	char bcast[SCAP_IPV6_ADDR_LEN];
	char ifname[SCAP_MAX_PATH_SIZE];
}scap_ifinfo_ipv6_nolinkspeed;

#if defined __sun
#pragma pack()
#else
#pragma pack(pop)
#endif

/*!
  \brief List of the machine network interfaces
*/
typedef struct scap_addrlist
{
	uint32_t n_v4_addrs; ///< Number of IPv4 addresses
	uint32_t n_v6_addrs; ///< Number of IPv6 addresses
	uint32_t totlen; ///< For internal use
	scap_ifinfo_ipv4* v4list; ///< List of IPv4 Addresses
	scap_ifinfo_ipv6* v6list; ///< List of IPv6 Addresses
}scap_addrlist;

#define MAX_CREDENTIALS_STR_LEN 256
#define USERBLOCK_TYPE_USER 0
#define USERBLOCK_TYPE_GROUP 1

/*!
  \brief Information about one of the machine users
*/
typedef struct scap_userinfo
{
	uint32_t uid; ///< User ID
	uint32_t gid; ///< Group ID
	char name[MAX_CREDENTIALS_STR_LEN]; ///< Username
	char homedir[SCAP_MAX_PATH_SIZE]; ///< Home directory
	char shell[SCAP_MAX_PATH_SIZE]; ///< Shell program
}scap_userinfo;

/*!
  \brief Information about one of the machine user groups
*/
typedef struct scap_groupinfo
{
	uint32_t gid; ///< Group ID
	char name[MAX_CREDENTIALS_STR_LEN]; ///< Group name
}scap_groupinfo;

/*!
  \brief List of the machine users and groups
*/
typedef struct scap_userlist
{
	uint32_t nusers; ///< Number of users
	uint32_t ngroups; ///< Number of groups
	uint32_t totsavelen; ///< For internal use
	scap_userinfo* users;  ///< User list
	scap_groupinfo* groups; ///< Group list
}scap_userlist;

//
// Misc definitions
//

/*!
  \brief The OS on which the capture was made
*/
typedef enum scap_os_platform
{
	SCAP_PFORM_UNKNOWN = 0,
	SCAP_PFORM_LINUX_I386 = 1,
	SCAP_PFORM_LINUX_X64 = 2,
	SCAP_PFORM_WINDOWS_I386 = 3,
	SCAP_PFORM_WINDOWS_X64 = 4,
}scap_os_platform;

/*!
  \brief Indicates if an event is an enter one or an exit one
*/
typedef enum event_direction
{
	SCAP_ED_IN = 0,
	SCAP_ED_OUT = 1
}event_direction;

/*!
  \brief Flags for scap_dump
*/
typedef enum scap_dump_flags
{
	SCAP_DF_NONE = 0,
	SCAP_DF_STATE_ONLY = 1,		///< The event should be used for state update but it should
								///< not be shown to the user
	SCAP_DF_TRACER = (1 << 1),	///< This event is a tracer
	SCAP_DF_LARGE = (1 << 2)	///< This event has large payload (up to UINT_MAX Bytes, ie 4GB)
}scap_dump_flags;

typedef struct scap_dumper scap_dumper_t;

/*!
  \brief System call description struct.
*/
struct ppm_syscall_desc {
	enum ppm_event_category category; /**< System call category. */
	char name[PPM_MAX_NAME_LEN]; /**< System call name, e.g. 'open'. */
};

/*!
  \brief Structure used to pass a buffer and its size.
*/
struct scap_sized_buffer {
	void* buf;
	size_t size;
};
typedef struct scap_sized_buffer scap_sized_buffer;

/*!
  \brief Structure used to pass a read-only buffer and its size.
*/
struct scap_const_sized_buffer {
	const void* buf;
	size_t size;
};
typedef struct scap_const_sized_buffer scap_const_sized_buffer;

/*@}*/

///////////////////////////////////////////////////////////////////////////////
// Structs and defines used internally
///////////////////////////////////////////////////////////////////////////////

#define IN
#define OUT

///////////////////////////////////////////////////////////////////////////////
// API functions
///////////////////////////////////////////////////////////////////////////////

/** @defgroup scap_functs API Functions
 *  @{
 */

/*!
  \brief Advanced function to start a capture.

  \param oargs a \ref scap_open_args structure containing the open parameters.
  \param error Pointer to a buffer that will contain the error string in case the
    function fails. The buffer must have size SCAP_LASTERR_SIZE.
  \param rc Integer pointer that will contain the scap return code in case the
    function fails.

  \return The capture instance handle in case of success. NULL in case of failure.
*/
scap_t* scap_open(scap_open_args* oargs, char *error, int32_t *rc);

/*!
  \brief Close a capture handle.

  \param handle Handle to the capture instance.
*/
void scap_close(scap_t* handle);

/*!
  \brief Restart the current event capture.
    Only supported for captures in SCAP_MODE_CAPTURE mode.
	This deinitializes the scap internal state, and then re-initializes
	it by trying to read the scap header section. The underlying instance
	of scap_reader_t is preserved, and the header section is read starting
	from its current offset.

  \param handle Handle to the capture instance.
*/
uint32_t scap_restart_capture(scap_t* handle);

/*!
  \brief Retrieve the OS platform for the given capture handle.

  \param handle Handle to the capture instance.

  \return The type of operating system on which the capture was made.

  \note For live handles, the return value indicates the current local OS.
    For offline handles, the return value indicates the OS where the data was
	originally captured.
*/
scap_os_platform scap_get_os_platform(scap_t* handle);

/*!
  \brief Return a string with the last error that happened on the given capture.
*/
const char* scap_getlasterr(scap_t* handle);

/*!
 * \brief returns the maximum amount of memory used by any driver queue
 */
uint64_t scap_max_buf_used(scap_t* handle);

/*!
  \brief Get the next event from the from the given capture instance

  \param handle Handle to the capture instance.
  \param pevent User-provided event pointer that will be initialized with address of the event.
  \param pcpuid User-provided event pointer that will be initialized with the ID if the CPU
    where the event was captured.

  \return SCAP_SUCCESS if the call is successful and pevent and pcpuid contain valid data.
   SCAP_TIMEOUT in case the read timeout expired and no event is available.
   SCAP_EOF when the end of an offline capture is reached.
   On Failure, SCAP_FAILURE is returned and scap_getlasterr() can be used to obtain the cause of the error.
*/
int32_t scap_next(scap_t* handle, OUT scap_evt** pevent, OUT uint16_t* pcpuid);

/*!
  \brief Get the length of an event

  \param e pointer to an event returned by \ref scap_next.

  \return The event length in bytes.
*/
uint32_t scap_event_getlen(scap_evt* e);

/*!
  \brief Get the timestamp of an event

  \param e pointer to an event returned by \ref scap_next.

  \return The event timestamp, in nanoseconds since epoch.
*/
uint64_t scap_event_get_ts(scap_evt* e);

/*!
  \brief Get the number of events that have been captured from the given capture
  instance

  \param handle Handle to the capture instance.

  \return The total number of events.
*/
uint64_t scap_event_get_num(scap_t* handle);

/*!
  \brief Reset the event count to 0.

  \param handle Handle to the capture instance.
*/
void scap_event_reset_count(scap_t* handle);

/*!
  \brief Return the meta-information describing the given event

  \param e pointer to an event returned by \ref scap_next.

  \return The pointer to the the event table entry for the given event.
*/
const struct ppm_event_info* scap_event_getinfo(const scap_evt* e);

/*!
  \brief Return the dump flags for the last event received from this handle

  \param handle Handle to the capture instance.

  \return The flags if the capture is offline, 0 if the capture is live.
*/
uint32_t scap_event_get_dump_flags(scap_t* handle);

/*!
  \brief Return the current offset in the file opened by scap_open_offline(),
  or -1 if this is a live capture.

  \param handle Handle to the capture instance.
*/
int64_t scap_get_readfile_offset(scap_t* handle);

/*!
  \brief Get the process list for the given capture instance

  \param handle Handle to the capture instance.

  \return Pointer to the process list.

  for live captures, the process list is created when the capture starts by scanning the
  proc file system. For offline captures, it is retrieved from the file.
  The process list contains information about the processes that were already open when
  the capture started. It can be traversed with uthash, using the following syntax:

  \code
  scap_threadinfo *pi;
  scap_threadinfo *tpi;
  scap_threadinfo *table = scap_get_proc_table(phandle);

  HASH_ITER(hh, table, pi, tpi)
  {
    // do something with pi
  }
  \endcode

  Refer to the documentation of the \ref scap_threadinfo struct for details about its
  content.
*/
scap_threadinfo* scap_get_proc_table(scap_t* handle);

/*!
  \brief Return the capture statistics for the given capture handle.

  \param handle Handle to the capture instance.
  \param stats Pointer to a \ref scap_stats structure that will be filled with the
  statistics.

  \return SCAP_SECCESS if the call is successful.
   On Failure, SCAP_FAILURE is returned and scap_getlasterr() can be used to obtain
   the cause of the error.
*/
int32_t scap_get_stats(scap_t* handle, OUT scap_stats* stats);

/*!
  \brief Returns the set of ppm_sc whose events have EF_MODIFIES_STATE flag or whose syscall have UF_NEVER_DROP flag.
*/
int scap_get_modifies_state_ppm_sc(OUT uint32_t ppm_sc_array[PPM_SC_MAX]);

/*!
  \brief Take an array of `ppm_sc` as input and provide the associated array of events as output.
*/
int scap_get_events_from_ppm_sc(IN uint32_t ppm_sc_array[PPM_SC_MAX], OUT uint32_t events_array[PPM_EVENT_MAX]);

/*!
  \brief Convert a native syscall nr to ppm_sc
*/
int scap_native_id_to_ppm_sc(int native_id);

/*!
  \brief Returns the set of minimum tracepoints required by `libsinsp` state.
*/
int scap_get_modifies_state_tracepoints(OUT uint32_t tp_array[TP_VAL_MAX]);

/*!
  \brief Get the system page size.
*/
unsigned long scap_get_system_page_size();

/*!
  \brief This function can be used to temporarily interrupt event capture.

  \param handle Handle to the capture that will be stopped.

  \return SCAP_SUCCESS if the call is successful.
   On Failure, SCAP_FAILURE is returned and scap_getlasterr() can be used to obtain
   the cause of the error.
*/
int32_t scap_stop_capture(scap_t* handle);

/*!
  \brief Start capture the events, if it was stopped with \ref scap_stop_capture.

  \param handle Handle to the capture that will be started.

  \return SCAP_SUCCESS if the call is successful.
   On Failure, SCAP_FAILURE is returned and scap_getlasterr() can be used to obtain
   the cause of the error.
*/
int32_t scap_start_capture(scap_t* handle);

/*!
  \brief Return the list of the the user interfaces of the machine from which the
  events are being captured.

  \param handle Handle to the capture instance.

  \return The pointer to a \ref scap_addrlist structure containing the interface list,
  or NULL if the function fails.
*/
scap_addrlist* scap_get_ifaddr_list(scap_t* handle);

/*!
  \brief Return the machine user and group lists

  \param handle Handle to the capture instance.

  \return The pointer to a \ref scap_userlist structure containing the user and
  group lists, or NULL if the function fails.
*/
scap_userlist* scap_get_user_list(scap_t* handle);

/*!
  \brief Retrieve the table with the description of every event type that
  the capture driver supports.

  \return The pointer to a table of \ref scap_userlist entries, each of which describes
  one of the events that can come from the driver. The table contains PPM_EVENT_MAX entries,
  and the position of each entry in the table corresponds to its event ID.
  The ppm_event_info contains the full information necessary to decode an event coming from
  \ref scap_next.
*/
const struct ppm_event_info* scap_get_event_info_table();

/*!
  \brief Retrieve the table with the description of system call that
  the capture driver supports.

  \return The pointer to a table of \ref ppm_syscall_desc entries, each of which describes
  one of the events that can come from the driver. The table contains SYSCALL_TABLE_SIZE entries,
  and the position of each entry in the table corresponds to the system call ID.

  This table can be used to interpret the ID parameter of PPME_GENERIC_E and PPME_GENERIC_X.
*/
const struct ppm_syscall_desc* scap_get_syscall_info_table();

/*!
  \brief Get generic machine information

  \return The pointer to a \ref scap_machine_info structure containing the information.

  \note for live captures, the information is collected from the operating system. For
  offline captures, it comes from the capture file.
*/
const scap_machine_info* scap_get_machine_info(scap_t* handle);

/*!
  \brief Set the capture snaplen, i.e. the maximum size an event parameter can
  reach before the driver starts truncating it.

  \param handle Handle to the capture instance.
  \param snaplen the snaplen for this capture instance, in bytes.

  \note This function can only be called for live captures.
  \note By default, the driver captures the first 80 bytes of the buffers coming from
  events like read, write, send, recv, etc.
  If you're not interested in payloads, smaller values will save capture buffer space and
  make capture files smaller.
  Conversely, big values should be used with care because they can easily generate huge
  capture files.
*/
int32_t scap_set_snaplen(scap_t* handle, uint32_t snaplen);

/*!
  \brief (Un)Set the ppm_sc bit in the syscall mask so that
  users can (drop)receive the related syscall. Useful for offloading
  operations such as evt.type=open

  \param handle Handle to the capture instance.
  \param ppm_sc id (example PPM_SC_EXECVE)
  \param enabled whether to enable or disable the syscall
  \note This function can only be called for live captures.
*/
int32_t scap_set_ppm_sc(scap_t* handle, uint32_t ppm_sc, bool enabled);

/*!
  \brief (Un)Set the tp into the tracepoint mask so that
  users can (detach)attach the requested tracepoint.

  \param handle Handle to the capture instance.
  \param tp id (example SYS_ENTER)
  \param enabled whether to enable or disable the tracepoint
  \note This function can only be called for live captures.
*/
int32_t scap_set_tpmask(scap_t* handle, uint32_t tp, bool enabled);


/*!
  \brief Get the root directory of the system. This usually changes
  if running in a container, so that all the information for the
  host can be correctly extracted.
*/
const char* scap_get_host_root();

/*!
  \brief Get the process list.
*/
struct ppm_proclist_info* scap_get_threadlist(scap_t* handle);

/*!
  \brief Check if the current engine name matches the provided engine_name
*/
bool scap_check_current_engine(scap_t *handle, const char* engine_name);

/*!
  \brief stop returning events for all subsequently spawned
  processes with the provided comm, as well as their children.
  This includes fork()/clone()ed processes that might later
  exec to a different comm.

  returns SCAP_FAILURE if there are already MAX_SUPPRESSED_COMMS comm
  values, SCAP_SUCCESS otherwise.
*/

int32_t scap_suppress_events_comm(scap_t* handle, const char *comm);

/*!
  \brief return whether the provided tid is currently being suppressed.
*/

bool scap_check_suppressed_tid(scap_t *handle, int64_t tid);

/*!
  \brief Get (at most) n parameters for this event.
 
  \param e The scap event.
  \param params An array large enough to contain at least one entry per event parameter (which is at most PPM_MAX_EVENT_PARAMS).
 */
uint32_t scap_event_decode_params(const scap_evt *e, struct scap_sized_buffer *params);

/*!
  \brief Create an event from the parameters given as arguments.

  Create any event from the event_table passing the type, n and the parameters as variadic arguments as follows:
   - Any integer type is passed from the correct type
   - String types (including PT_FSPATH, PT_FSRELPATH) are passed via a null-terminated char*
   - Buffer types, variable size types and similar, including PT_BYTEBUF, PT_SOCKTUPLE are passed with
     a struct scap_const_sized_buffer
  
  If the event was written successfully, SCAP_SUCCESS is returned. If the supplied buffer is not large enough to contain
  the event, SCAP_INPUT_TOO_SMALL is returned and event_size is set with the required size to contain the entire event.

  \param event_buf The buffer where to store the encoded event.
  \param event_size Output value that will be filled with the size of the event.
  \param error A pointer to a scap error string to be filled in case of error.
  \param event_type The event type (normally PPME_*)
  \param n The number of parameters for this event. This is required as the number of parameters used for each event can change between versions.
  \param ...
  \return int32_t The error value. If the event was written successfully, SCAP_SUCCESS is returned.
  If the supplied buffer is not large enough for the event SCAP_INPUT_TOO_SMALL is returned and event_size
  is set with the required size to contain the entire event. In other error cases, SCAP_FAILURE is returned.

 */
int32_t scap_event_encode_params(struct scap_sized_buffer event_buf, size_t *event_size, char *error, enum ppm_event_type event_type, uint32_t n, ...);
int32_t scap_event_encode_params_v(struct scap_sized_buffer event_buf, size_t *event_size, char *error, enum ppm_event_type event_type, uint32_t n, va_list args);

/*@}*/

///////////////////////////////////////////////////////////////////////////////
// Non public functions
///////////////////////////////////////////////////////////////////////////////

//
// Return the number of event capture devices that the library is handling. Each processor
// has its own event capture device.
//
uint32_t scap_get_ndevs(scap_t* handle);

// Retrieve a buffer of events from one of the cpus
extern int32_t scap_readbuf(scap_t* handle, uint32_t cpuid, OUT char** buf, OUT uint32_t* len);

#ifdef PPM_ENABLE_SENTINEL
// Get the sentinel at the beginning of the event
uint32_t scap_event_get_sentinel_begin(scap_evt* e);
#endif

// Get the information about a process.
// The returned pointer must be freed via scap_proc_free by the caller.
struct scap_threadinfo* scap_proc_get(scap_t* handle, int64_t tid, bool scan_sockets);

// Check if the given thread exists in ;proc
bool scap_is_thread_alive(scap_t* handle, int64_t pid, int64_t tid, const char* comm);

// like getpid() but returns the global PID even inside a container
int32_t scap_getpid_global(scap_t* handle, int64_t* pid);

struct scap_threadinfo *scap_proc_alloc(scap_t* handle);
void scap_proc_free(scap_t* handle, struct scap_threadinfo* procinfo);
void scap_dev_delete(scap_t* handle, scap_mountinfo* dev);
int32_t scap_stop_dropping_mode(scap_t* handle);
int32_t scap_start_dropping_mode(scap_t* handle, uint32_t sampling_ratio);
int32_t scap_enable_dynamic_snaplen(scap_t* handle);
int32_t scap_disable_dynamic_snaplen(scap_t* handle);
void scap_free_device_table(scap_t* handle);
void scap_refresh_iflist(scap_t* handle);
void scap_refresh_proc_table(scap_t* handle);
uint64_t scap_ftell(scap_t *handle);
void scap_fseek(scap_t *handle, uint64_t off);
int32_t scap_enable_tracers_capture(scap_t* handle);
int32_t scap_proc_add(scap_t* handle, uint64_t tid, scap_threadinfo* tinfo);
int32_t scap_fd_add(scap_t *handle, scap_threadinfo* tinfo, uint64_t fd, scap_fdinfo* fdinfo);
// Variant of scap_write_proclist_entry where array-backed information
// about the thread is provided separate from the scap_threadinfo
// struct.
int32_t scap_write_proclist_entry_bufs(scap_dumper_t *d, struct scap_threadinfo *tinfo, uint32_t *len,
				       const char *comm,
				       const char *exe,
				       const char *exepath,
				       const struct iovec *args, int argscnt,
				       const struct iovec *envs, int envscnt,
				       const char *cwd,
				       const struct iovec *cgroups, int cgroupscnt,
				       const char *root);

int32_t scap_get_n_tracepoint_hit(scap_t* handle, long* ret);
int32_t scap_set_fullcapture_port_range(scap_t* handle, uint16_t range_start, uint16_t range_end);

/**
 * By default we have an expanded snaplen for the default statsd port. If the
 * statsd port is non-standard, communicate that port value to the kernel to
 * get the expanded snaplen for the correct port.
 */
int32_t scap_set_statsd_port(scap_t* handle, uint16_t port);

/**
 * Is `driver_api_version` compatible with `required_api_version`?
 */
bool scap_is_api_compatible(unsigned long driver_api_version, unsigned long required_api_version);

/**
 * Apply the `semver` checks on current and required versions.
 */  
bool scap_apply_semver_check(uint32_t current_major, uint32_t current_minor, uint32_t current_patch,
							uint32_t required_major, uint32_t required_minor, uint32_t required_patch);

/**
 * Get API version supported by the driver
 */
uint64_t scap_get_driver_api_version(scap_t* handle);

/**
 * Get schema version supported by the driver
 */
uint64_t scap_get_driver_schema_version(scap_t* handle);

/**
 * This helper returns the system boot time computed as the actual time - the uptime of the system since the boot.
 * We need to use this helper in drivers like BPF, because in BPF we are not able to obtain the current system time
 * since Epoch, so we need to compute it as `time_from_the_boot(bpf_ktime_get_boot_ns) + boot_time`.
 */
int32_t scap_get_boot_time(char* last_err, uint64_t *boot_time);

#ifdef __cplusplus
}
#endif

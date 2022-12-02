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

////////////////////////////////////////////////////////////////////////////
// Private definitions for the scap library
////////////////////////////////////////////////////////////////////////////

#pragma once

#ifndef SCAP_HANDLE_T
#define SCAP_HANDLE_T void
#endif

#include "engine_handle.h"
#include "scap_vtable.h"

#include "settings.h"
#include "plugin_info.h"
#include "scap_assert.h"
#include "scap_suppress.h"
#include "scap_zlib.h"

#ifdef __cplusplus
extern "C" {
#endif

//
// Process flags
//
#define PF_CLONING 1

//
// The open instance handle
//
struct scap
{
	const struct scap_vtable *m_vtable;
	struct scap_engine_handle m_engine;
	struct scap_suppress m_suppress;

	scap_mode_t m_mode;
	char m_lasterr[SCAP_LASTERR_SIZE];

	struct scap_proclist m_proclist;
	scap_mountinfo* m_dev_list;
	uint64_t m_evtcnt;
	scap_addrlist* m_addrlist;
	scap_machine_info m_machine_info;
	scap_userlist* m_userlist;
	struct ppm_proclist_info* m_driver_procinfo;
	uint32_t m_fd_lookup_limit;
	uint8_t m_cgroup_version;

	// API version supported by the driver
	// If the API version is unavailable for whatever reason,
	// it's equivalent to version 0.0.0
	uint64_t m_api_version;

	// schema version supported by the driver
	// If the schema version is unavailable for whatever reason,
	// it's equivalent to version 0.0.0
	uint64_t m_schema_version;

	// /proc scan parameters
	uint64_t m_proc_scan_timeout_ms;
	uint64_t m_proc_scan_log_interval_ms;

	// Function which may be called to log a debug event
	void(*m_debug_log_fn)(const char* msg);
};

typedef enum ppm_dumper_type
{
	DT_FILE = 0,
	DT_MEM = 1,
	DT_MANAGED_BUF = 2,
}ppm_dumper_type;

#define PPM_DUMPER_MANAGED_BUF_SIZE (3 * 1024 * 1024)
#define PPM_DUMPER_MANAGED_BUF_RESIZE_FACTOR (1.25)

struct scap_dumper
{
	gzFile m_f;
	ppm_dumper_type m_type;
	uint8_t* m_targetbuf;
	uint8_t* m_targetbufcurpos;
	uint8_t* m_targetbufend;
};

struct scap_ns_socket_list
{
	int64_t net_ns;
	scap_fdinfo* sockets;
	UT_hash_handle hh;
};

//
// Misc stuff
//
#define MEMBER_SIZE(type, member) sizeof(((type *)0)->member)
#define READER_BUF_SIZE (1 << 16) // UINT16_MAX + 1, ie: 65536

//
// Internal library functions
//

// Read the full event buffer for the given processor
int32_t scap_readbuf(scap_t* handle, uint32_t proc, OUT char** buf, OUT uint32_t* len);
// Read a single thread info from /proc
int32_t scap_proc_read_thread(scap_t* handle, char* procdirname, uint64_t tid, struct scap_threadinfo** pi, char *error, bool scan_sockets);
// Scan a directory containing process information
int32_t scap_proc_scan_proc_dir(scap_t* handle, char* procdirname, char *error);
// Scan process information from engine vtable
int32_t scap_proc_scan_vtable(char *error, scap_t *handle);
// Free the process table
void scap_proc_free_table(struct scap_proclist* proclist);
// Return the process info entry given a tid
// Free an fd table and set it to NULL when done
void scap_fd_free_table(scap_fdinfo** fds);
// Free a process' fd table
void scap_fd_free_proc_fd_table(scap_threadinfo* pi);
// Calculate the length on disk of an fd entry's info
uint32_t scap_fd_info_len(scap_fdinfo* fdi);
// Write the given fd info to disk
int32_t scap_fd_write_to_disk(scap_t* handle, scap_fdinfo* fdi, scap_dumper_t* dumper, uint32_t len);
// Add the file descriptor info pointed by fdi to the fd table for process pi.
// Note: silently skips if fdi->type is SCAP_FD_UNKNOWN.
int32_t scap_add_fd_to_proc_table(struct scap_proclist* proclist, scap_threadinfo* pi, scap_fdinfo* fdi, char *error);
// Remove the given fd from the process table of the process pointed by pi
void scap_fd_remove(scap_t* handle, scap_threadinfo* pi, int64_t fd);
// read the file descriptors for a given process directory
int32_t scap_fd_scan_fd_dir(scap_t* handle, char * procdir, scap_threadinfo* pi, struct scap_ns_socket_list** sockets_by_ns, char *error);
// scan fd information for a specific thread from engine vtable. src_tinfo is a pointer to a threadinfo returned by the engine
int32_t scap_fd_scan_vtable(scap_t *handle, const scap_threadinfo *src_tinfo, scap_threadinfo *dst_tinfo, char *error);
// get the device major/minor number for the requested_mount_id, looking in procdir/mountinfo if needed
uint32_t scap_get_device_by_mount_id(scap_t *handle, const char *procdir, unsigned long requested_mount_id);
// Allocate and return the list of interfaces on this system
int32_t scap_create_iflist(scap_t* handle);
// Free a previously allocated list of interfaces
void scap_free_iflist(scap_addrlist* ifhandle);
// Allocate and return the list of users on this system
int32_t scap_create_userlist(scap_t* handle);
// Free a previously allocated list of users
void scap_free_userlist(scap_userlist* uhandle);
// Allocate a file descriptor
int32_t scap_fd_allocate_fdinfo(scap_fdinfo **fdi, int64_t fd, scap_fd_type type);
// Free a file descriptor
void scap_fd_free_fdinfo(scap_fdinfo **fdi);

int32_t scap_proc_fill_cgroups_pidns_start_ts(char* error, int cgroup_version, struct scap_threadinfo* tinfo, const char* procdirname);

bool scap_alloc_proclist_info(struct ppm_proclist_info **proclist_p, uint32_t n_entries, char* error);

// Determine whether or not the provided event should be suppressed,
// based on its event type and parameters. May update the set of
// suppressed tids as a side-effect.
//
// Returns SCAP_FAILURE if we tried to add the tid to the suppressed
// tid set, but it could *not* be added, SCAP_SUCCESS otherwise.
int32_t scap_check_suppressed(struct scap_suppress *suppress, scap_evt *pevent,
			      bool *suppressed, char *error);

int32_t scap_procfs_get_threadlist(struct scap_engine_handle engine, struct ppm_proclist_info **procinfo_p, char *lasterr);
int32_t scap_os_getpid_global(struct scap_engine_handle engine, int64_t *pid, char* error);

//
// Useful stuff
//
#ifndef MIN
#define MIN(X,Y) ((X) < (Y)? (X):(Y))
#define MAX(X,Y) ((X) > (Y)? (X):(Y))
#endif


//
// Driver proc info table sizes
//
#define SCAP_DRIVER_PROCINFO_INITIAL_SIZE 7
#define SCAP_DRIVER_PROCINFO_MAX_SIZE 128000

extern const struct syscall_evt_pair g_syscall_table[];
extern const struct ppm_event_info g_event_info[];
extern const struct ppm_event_entry g_ppm_events[];

//
// udig stuff
//
int32_t udig_begin_capture(struct scap_engine_handle engine, char *error);

#ifdef __cplusplus
}
#endif

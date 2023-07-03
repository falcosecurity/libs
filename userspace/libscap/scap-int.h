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
#include "scap_assert.h"
#include "scap_suppress.h"

#ifdef __linux__
#include "linux/scap_cgroup.h"
#endif // __linux__

#ifdef __cplusplus
extern "C" {
#endif

//
// The open instance handle
//
struct scap
{
	const struct scap_vtable *m_vtable;
	struct scap_engine_handle m_engine;
	struct scap_platform *m_platform;

	char m_lasterr[SCAP_LASTERR_SIZE];

	uint64_t m_evtcnt;

	// Function which may be called to log a debug event
	void(*m_debug_log_fn)(const char* msg);
};

//
// Internal library functions
//

// Free the process table
void scap_proc_free_table(struct scap_proclist* proclist);
// Return the process info entry given a tid
// Free an fd table and set it to NULL when done
void scap_fd_free_table(scap_fdinfo** fds);
// Free a process' fd table
void scap_fd_free_proc_fd_table(scap_threadinfo* pi);
// Add the file descriptor info pointed by fdi to the fd table for process pi.
// Note: silently skips if fdi->type is SCAP_FD_UNKNOWN.
int32_t scap_add_fd_to_proc_table(struct scap_proclist* proclist, scap_threadinfo* pi, scap_fdinfo* fdi, char *error);
// Free a previously allocated list of interfaces
void scap_free_iflist(scap_addrlist* ifhandle);
// Free a previously allocated list of users
void scap_free_userlist(scap_userlist* uhandle);
// Allocate a file descriptor
int32_t scap_fd_allocate_fdinfo(scap_fdinfo **fdi, int64_t fd, scap_fd_type type);
// Free a file descriptor
void scap_fd_free_fdinfo(scap_fdinfo **fdi);

int32_t scap_proc_fill_pidns_start_ts(char* error, struct scap_threadinfo* tinfo, const char* procdirname);

bool scap_alloc_proclist_info(struct ppm_proclist_info **proclist_p, uint32_t n_entries, char* error);

void scap_free_device_table(scap_mountinfo* dev_list);

// Determine whether or not the provided event should be suppressed,
// based on its event type and parameters. May update the set of
// suppressed tids as a side-effect.
//
// Returns SCAP_FAILURE if we tried to add the tid to the suppressed
// tid set, but it could *not* be added, SCAP_SUCCESS otherwise.
int32_t scap_check_suppressed(struct scap_suppress *suppress, scap_evt *pevent,
			      uint16_t devid, bool *suppressed, char *error);

//
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

#ifdef __cplusplus
}
#endif

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

#include <stdbool.h>
#include <stdint.h>

// this header is designed to be useful to scap consumers,
// using the scap_t wrapper functions

#ifdef __cplusplus
extern "C" {
#endif

struct ppm_proclist_info;
struct scap;
struct scap_addrlist;
struct _scap_machine_info;
struct scap_platform;
struct scap_threadinfo;
typedef struct _scap_agent_info scap_agent_info;

/*!
  \brief Return the list of the the user interfaces of the machine from which the
  events are being captured.

  \param platform Handle to the platform instance.

  \return The pointer to a \ref scap_addrlist structure containing the interface list,
  or NULL if the function fails.
*/
struct scap_addrlist* scap_get_ifaddr_list(struct scap_platform* platform);

void scap_refresh_iflist(struct scap_platform* platform);

/*!
  \brief Return the machine user and group lists

  \param platform Handle to the platform instance.

  \return The pointer to a \ref scap_userlist structure containing the user and
  group lists, or NULL if the function fails.
*/
struct scap_userlist* scap_get_user_list(struct scap_platform* platform);

// get the device major/minor number for the requested_mount_id, looking in procdir/mountinfo if needed
// XXX: procdir is Linux-specific
uint32_t scap_get_device_by_mount_id(struct scap_platform* platform, const char *procdir, unsigned long requested_mount_id);

// Get the information about a process.
// The returned pointer must be freed via scap_proc_free by the caller.
int32_t scap_proc_get(struct scap_platform* platform, int64_t tid, struct scap_threadinfo* tinfo,
		       bool scan_sockets);

int32_t scap_refresh_proc_table(struct scap_platform* platform);

// Check if the given thread exists in /proc
bool scap_is_thread_alive(struct scap_platform* platform, int64_t pid, int64_t tid, const char* comm);

// like getpid() but returns the global PID even inside a container
int32_t scap_getpid_global(struct scap_platform* platform, int64_t* pid);

/*!
  \brief Get generic machine information

  \return The pointer to a \ref scap_machine_info structure containing the information.

  \note for live captures, the information is collected from the operating system. For
  offline captures, it comes from the capture file.
*/
const struct _scap_machine_info* scap_get_machine_info(struct scap_platform* platform);

/*!
  \brief Get generic agent information

  \return The pointer to a \ref scap_agent_info structure containing the information.

  \note for live captures only.
*/
const scap_agent_info* scap_get_agent_info(struct scap_platform* platform);

/*!
  \brief Get the process list.
*/
struct ppm_proclist_info* scap_get_threadlist(struct scap_platform* platform, char* error);

/*!
  \brief Get the file descriptor list for a given pid.
*/
int32_t scap_get_fdlist(struct scap_platform* platform, struct scap_threadinfo* tinfo, char* error);

#ifdef __cplusplus
};
#endif

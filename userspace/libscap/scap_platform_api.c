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

#include <stdio.h>

#include <libscap/scap_platform_api.h>
#include <libscap/scap_platform_impl.h>

#include <libscap/scap.h>
#include <libscap/scap-int.h>

scap_addrlist* scap_get_ifaddr_list(struct scap_platform* platform)
{
	if (platform)
	{
		return platform->m_addrlist;
	}

	return NULL;
}

void scap_refresh_iflist(struct scap_platform* platform)
{
	if (platform && platform->m_vtable->refresh_addr_list)
	{
		platform->m_vtable->refresh_addr_list(platform);
	}
}

scap_userlist* scap_get_user_list(struct scap_platform* platform)
{
	if (platform)
	{
		return platform->m_userlist;
	}

	return NULL;
}

uint32_t scap_get_device_by_mount_id(struct scap_platform* platform, const char *procdir, unsigned long requested_mount_id)
{
	if (platform && platform->m_vtable->get_device_by_mount_id)
	{
		return platform->m_vtable->get_device_by_mount_id(platform, procdir, requested_mount_id);
	}

	return 0;
}

int32_t scap_proc_get(struct scap_platform* platform, int64_t tid, struct scap_threadinfo* tinfo,
		       bool scan_sockets)
{
	if (platform && platform->m_vtable->get_proc)
	{
		return platform->m_vtable->get_proc(platform, tid, tinfo, scan_sockets);
	}

	return SCAP_FAILURE;
}

int32_t scap_refresh_proc_table(struct scap_platform* platform)
{
	if (platform && platform->m_vtable->refresh_proc_table)
	{
		return platform->m_vtable->refresh_proc_table(platform, &platform->m_proclist);
	}

	return SCAP_FAILURE;
}

bool scap_is_thread_alive(struct scap_platform* platform, int64_t pid, int64_t tid, const char* comm)
{
	if (platform && platform->m_vtable->is_thread_alive)
	{
		return platform->m_vtable->is_thread_alive(platform, pid, tid, comm);
	}

	// keep on the safe side, don't consider threads dead too early
	return true;
}

int32_t scap_getpid_global(struct scap_platform* platform, int64_t* pid)
{
	if (platform == NULL)
	{
		ASSERT(false);
		return SCAP_FAILURE;
	}

	if (platform->m_vtable->get_global_pid == NULL)
	{
		return SCAP_NOT_SUPPORTED;
	}

	char lasterr[SCAP_LASTERR_SIZE];
	return platform->m_vtable->get_global_pid(platform, pid, lasterr);
}

const scap_machine_info* scap_get_machine_info(struct scap_platform* platform)
{
	if(platform)
	{
		scap_machine_info* machine_info = &platform->m_machine_info;
		if(machine_info->num_cpus != (uint32_t)-1)
		{
			return machine_info;
		}
	}

	//
	// Reading from a file with no process info block
	//
	return NULL;
}

//
// Get the agent information
//
const scap_agent_info* scap_get_agent_info(struct scap_platform* platform)
{
	if(platform)
	{
		return (const scap_agent_info*)&platform->m_agent_info;
	}

	return NULL;
}

struct ppm_proclist_info* scap_get_threadlist(struct scap_platform* platform, char* error)
{
	if (platform && platform->m_vtable->get_threadlist)
	{
		if(platform->m_vtable->get_threadlist(platform, &platform->m_driver_procinfo, error) == SCAP_SUCCESS)
		{
			return platform->m_driver_procinfo;
		}
		return NULL;
	}

	snprintf(error, SCAP_LASTERR_SIZE, "operation not supported");
	return NULL;
}

int32_t scap_get_fdlist(struct scap_platform* platform, struct scap_threadinfo* tinfo, char* error)
{
	if (platform && platform->m_vtable->get_fdlist)
	{	
		return platform->m_vtable->get_fdlist(platform, tinfo, error);
	}

	snprintf(error, SCAP_LASTERR_SIZE, "operation not supported");
	return SCAP_FAILURE;
}

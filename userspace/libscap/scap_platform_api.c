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

#include "scap_platform_api.h"
#include "scap_platform_impl.h"

#include "scap.h"
#include "scap-int.h"

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

struct scap_threadinfo* scap_proc_get(struct scap_platform* platform, int64_t tid, bool scan_sockets)
{
	if (platform && platform->m_vtable->get_proc)
	{
		return platform->m_vtable->get_proc(platform, &platform->m_proclist, tid, scan_sockets);
	}

	return NULL;
}

int32_t scap_refresh_proc_table(struct scap_platform* platform)
{
	if (platform && platform->m_vtable->refresh_proc_table)
	{
		return platform->m_vtable->refresh_proc_table(platform, &platform->m_proclist);
	}

	return SCAP_FAILURE;
}

scap_threadinfo* scap_get_proc_table(struct scap_platform* platform)
{
	if (platform)
	{
		return platform->m_proclist.m_proclist;
	}

	return NULL;
}

bool scap_is_thread_alive(scap_t* handle, int64_t pid, int64_t tid, const char* comm)
{
	if (handle && handle->m_platform && handle->m_platform->m_vtable->is_thread_alive)
	{
		return handle->m_platform->m_vtable->is_thread_alive(handle->m_platform, pid, tid, comm);
	}

	// keep on the safe side, don't consider threads dead too early
	return true;
}

int32_t scap_getpid_global(scap_t* handle, int64_t* pid)
{
	if (handle && handle->m_platform && handle->m_platform->m_vtable->get_global_pid)
	{
		return handle->m_platform->m_vtable->get_global_pid(handle->m_platform, pid, handle->m_lasterr);
	}

	ASSERT(false);
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Cannot get pid (capture not enabled)");
	return SCAP_FAILURE;
}

const scap_machine_info* scap_get_machine_info(scap_t* handle)
{
	if(handle && handle->m_platform)
	{
		scap_machine_info* machine_info = &handle->m_platform->m_machine_info;
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
const scap_agent_info* scap_get_agent_info(scap_t* handle)
{
	if(handle && handle->m_platform)
	{
		return (const scap_agent_info*)&handle->m_platform->m_agent_info;
	}

	return NULL;
}

struct ppm_proclist_info* scap_get_threadlist(scap_t* handle)
{
	if (handle && handle->m_platform && handle->m_platform->m_vtable->get_threadlist)
	{
		if(handle->m_platform->m_vtable->get_threadlist(handle->m_platform, &handle->m_platform->m_driver_procinfo, handle->m_lasterr) == SCAP_SUCCESS)
		{
			return handle->m_platform->m_driver_procinfo;
		}
		return NULL;
	}

	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "operation not supported");
	return NULL;
}


int32_t scap_get_fdlist(struct scap* handle, struct scap_threadinfo *tinfo)
{
	if (handle && handle->m_platform && handle->m_platform->m_vtable->get_fdlist)
	{	
		return handle->m_platform->m_vtable->get_fdlist(handle->m_platform, tinfo, handle->m_lasterr);
	}

	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "operation not supported");
	return SCAP_FAILURE;
}

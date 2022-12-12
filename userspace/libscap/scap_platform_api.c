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

#include <stdio.h>

#include "scap_platform_api.h"
#include "scap_platform_impl.h"

#include "scap.h"
#include "scap-int.h"

scap_addrlist* scap_get_ifaddr_list(scap_t* handle)
{
	if (handle && handle->m_platform)
	{
		return handle->m_platform->m_addrlist;
	}

	return NULL;
}

void scap_refresh_iflist(scap_t* handle)
{
	if (handle && handle->m_platform && handle->m_platform->m_vtable->refresh_addr_list)
	{
		handle->m_platform->m_vtable->refresh_addr_list(handle->m_platform);
	}
}

scap_userlist* scap_get_user_list(scap_t* handle)
{
	if (handle && handle->m_platform)
	{
		return handle->m_platform->m_userlist;
	}

	return NULL;
}

uint32_t scap_get_device_by_mount_id(scap_t *handle, const char *procdir, unsigned long requested_mount_id)
{
	if (handle && handle->m_platform && handle->m_platform->m_vtable->get_device_by_mount_id)
	{
		return handle->m_platform->m_vtable->get_device_by_mount_id(handle->m_platform, procdir, requested_mount_id);
	}

	return 0;
}

struct scap_threadinfo* scap_proc_get(scap_t* handle, int64_t tid, bool scan_sockets)
{
	if (handle && handle->m_platform && handle->m_platform->m_vtable->get_proc)
	{
		return handle->m_platform->m_vtable->get_proc(handle->m_platform, &handle->m_platform->m_proclist, tid, scan_sockets);
	}

	return NULL;
}

int32_t scap_refresh_proc_table(scap_t* handle)
{
	if (handle && handle->m_platform && handle->m_platform->m_vtable->refresh_proc_table)
	{
		return handle->m_platform->m_vtable->refresh_proc_table(handle->m_platform, &handle->m_platform->m_proclist);
	}

	return SCAP_FAILURE;
}

scap_threadinfo* scap_get_proc_table(scap_t* handle)
{
	if (handle && handle->m_platform)
	{
		return handle->m_platform->m_proclist.m_proclist;
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

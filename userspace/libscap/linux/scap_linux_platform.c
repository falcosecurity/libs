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

#include <libscap/linux/scap_linux_platform.h>

#include <libscap/scap.h>
#include <libscap/scap-int.h>
#include <libscap/scap_machine_info.h>
#include <libscap/linux/scap_linux_int.h>

#include <libscap/compat/misc.h>

#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/time.h>
#include <unistd.h>

static int32_t scap_linux_close_platform(struct scap_platform* platform)
{
	struct scap_linux_platform* linux_platform = (struct scap_linux_platform*)platform;

	// Free the device table
	if(linux_platform->m_dev_list != NULL)
	{
		scap_free_device_table(linux_platform->m_dev_list);
		linux_platform->m_dev_list = NULL;
	}

	scap_cgroup_clear_cache(&linux_platform->m_cgroups);

	return SCAP_SUCCESS;
}

static void scap_linux_free_platform(struct scap_platform* platform)
{
	free(platform);
}

int32_t scap_linux_init_platform(struct scap_platform* platform, char* lasterr, struct scap_engine_handle engine, struct scap_open_args* oargs)
{
	int rc;
	struct scap_linux_platform* linux_platform = (struct scap_linux_platform*)platform;
	linux_platform->m_lasterr = lasterr;
	linux_platform->m_engine = engine;
	linux_platform->m_proc_scan_timeout_ms = oargs->proc_scan_timeout_ms;
	linux_platform->m_proc_scan_log_interval_ms = oargs->proc_scan_log_interval_ms;
	linux_platform->m_log_fn = oargs->log_fn;

	if(scap_os_get_machine_info(&platform->m_machine_info, lasterr) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}

	scap_os_get_agent_info(&platform->m_agent_info);

	rc = scap_linux_create_iflist(platform);
	if(rc != SCAP_SUCCESS)
	{
		scap_linux_free_platform(platform);
		return rc;
	}

	if(oargs->import_users)
	{
		rc = scap_linux_create_userlist(platform);
		if(rc != SCAP_SUCCESS)
		{
			scap_linux_free_platform(platform);
			return rc;
		}
	}

	rc = scap_cgroup_interface_init(&linux_platform->m_cgroups, scap_get_host_root(), lasterr, true);
	if(rc != SCAP_SUCCESS)
	{
		scap_linux_free_platform(platform);
		return rc;
	}

	linux_platform->m_lasterr[0] = '\0';
	char proc_scan_err[SCAP_LASTERR_SIZE];
	rc = scap_linux_refresh_proc_table(platform, &platform->m_proclist);
	if(rc != SCAP_SUCCESS)
	{
		snprintf(linux_platform->m_lasterr, SCAP_LASTERR_SIZE, "scap_open_live_int() error creating the process list: %s. Make sure you have root credentials.", proc_scan_err);
		scap_linux_free_platform(platform);
		return rc;
	}

	return SCAP_SUCCESS;
}

static const struct scap_platform_vtable scap_linux_platform_vtable = {
	.init_platform = scap_linux_init_platform,
	.refresh_addr_list = scap_linux_create_iflist,
	.get_device_by_mount_id = scap_linux_get_device_by_mount_id,
	.get_proc = scap_linux_proc_get,
	.refresh_proc_table = scap_linux_refresh_proc_table,
	.is_thread_alive = scap_linux_is_thread_alive,
	.get_global_pid = scap_linux_getpid_global,
	.get_threadlist = scap_linux_get_threadlist,
	.get_fdlist = scap_linux_get_fdlist,
	.close_platform = scap_linux_close_platform,
	.free_platform = scap_linux_free_platform,
};

struct scap_platform* scap_linux_alloc_platform(proc_entry_callback proc_callback, void* proc_callback_context)
{
	struct scap_linux_platform* platform = calloc(sizeof(*platform), 1);

	if(platform == NULL)
	{
		return NULL;
	}

	struct scap_platform* generic = &platform->m_generic;
	generic->m_vtable = &scap_linux_platform_vtable;

	init_proclist(&generic->m_proclist, proc_callback, proc_callback_context);

	return generic;
}

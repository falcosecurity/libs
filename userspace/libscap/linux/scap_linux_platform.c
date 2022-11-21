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

#include "scap_linux_platform.h"

#include "scap.h"
#include "scap-int.h"
#include "scap_linux_int.h"
#include "strerror.h"

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

static int32_t scap_linux_close_platform(struct scap_platform* platform)
{
	struct scap_linux_platform* linux_platform = (struct scap_linux_platform*)platform;

	// Free the device table
	if(linux_platform->m_dev_list != NULL)
	{
		scap_free_device_table(linux_platform->m_dev_list);
		linux_platform->m_dev_list = NULL;
	}

	return SCAP_SUCCESS;
}

static void scap_linux_free_platform(struct scap_platform* platform)
{
	free(platform);
}

static int scap_get_cgroup_version()
{
	char dir_name[256];
	int cgroup_version = -1;
	FILE* f;
	char line[SCAP_MAX_ENV_SIZE];

	snprintf(dir_name, sizeof(dir_name), "%s/proc/filesystems", scap_get_host_root());
	f = fopen(dir_name, "r");
	if (f)
	{
		while(fgets(line, sizeof(line), f) != NULL)
		{
			// NOTE: we do not support mixing cgroups v1 v2 controllers.
			// Neither docker nor podman support this: https://github.com/docker/for-linux/issues/1256
			if (strstr(line, "cgroup2"))
			{
				return 2;
			}
			if (strstr(line, "cgroup"))
			{
				cgroup_version = 1;
			}
		}
		fclose(f);
	}

	return cgroup_version;
}

int32_t scap_linux_early_init_platform(struct scap_platform* platform, char* lasterr, struct scap_open_args* oargs)
{
	struct scap_linux_platform* linux_platform = (struct scap_linux_platform*)platform;
	linux_platform->m_lasterr = lasterr;

	linux_platform->m_proc_scan_timeout_ms = oargs->proc_scan_timeout_ms;
	linux_platform->m_proc_scan_log_interval_ms = oargs->proc_scan_log_interval_ms;
	linux_platform->m_debug_log_fn = oargs->debug_log_fn;

	linux_platform->m_cgroup_version = scap_get_cgroup_version();
	if(linux_platform->m_cgroup_version < 1)
	{
		ASSERT(false);
		return scap_errprintf(lasterr, errno, "failed to fetch cgroup version information");
	}

	return SCAP_SUCCESS;
}

int32_t scap_linux_init_platform(struct scap_platform* platform, struct scap_engine_handle engine, struct scap_open_args* oargs)
{
	int rc;

	struct scap_linux_platform* linux_platform = (struct scap_linux_platform*)platform;
	linux_platform->m_engine = engine;

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

static const struct scap_platform_vtable scap_linux_platform = {
	.early_init_platform = scap_linux_early_init_platform,
	.init_platform = scap_linux_init_platform,
	.refresh_addr_list = scap_linux_create_iflist,
	.get_device_by_mount_id = scap_linux_get_device_by_mount_id,
	.get_proc = scap_linux_proc_get,
	.refresh_proc_table = scap_linux_refresh_proc_table,
	.is_thread_alive = scap_linux_is_thread_alive,
	.close_platform = scap_linux_close_platform,
	.free_platform = scap_linux_free_platform,
};

struct scap_platform* scap_linux_alloc_platform()
{
	struct scap_linux_platform* platform = calloc(sizeof(*platform), 1);

	if(platform == NULL)
	{
		return NULL;
	}

	struct scap_platform* generic = &platform->m_generic;
	generic->m_vtable = &scap_linux_platform;

	return generic;
}

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

#include "scap_linux_platform.h"

#include "scap.h"
#include "scap-int.h"
#include "scap_linux_int.h"

#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/utsname.h>

#define SECOND_TO_NS 1000000000

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

static void scap_linux_retrieve_agent_info(scap_agent_info* agent_info)
{
	agent_info->start_ts_epoch = 0;
	agent_info->start_time = 0;

	/* Info 1:
	 *
	 * Get epoch timestamp based on procfs stat, only used for (constant) agent start time reporting.
	 */
	struct stat st = {0};
	if(stat("/proc/self/cmdline", &st) == 0)
	{
		agent_info->start_ts_epoch = st.st_ctim.tv_sec * (uint64_t) SECOND_TO_NS + st.st_ctim.tv_nsec;
	}

	/* Info 2:
	 *
	 * Get /proc/self/stat start_time (22nd item) to calculate subsequent snapshots of the elapsed time
	 * of the agent for CPU usage calculations, e.g. sysinfo uptime - /proc/self/stat start_time.
	 */
	FILE* f;
	if((f = fopen("/proc/self/stat", "r")))
	{
		unsigned long long stat_start_time = 0; // unit: USER_HZ / jiffies / clock ticks
		long hz = 100;
#ifdef _SC_CLK_TCK
		if ((hz = sysconf(_SC_CLK_TCK)) < 0)
		{
			hz = 100;
			ASSERT(false);
		}
#endif
		if(fscanf(f, "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %*u %*u %*u %*u %*d %*d %*d %*u %llu", &stat_start_time))
		{
			agent_info->start_time = (double)stat_start_time / hz; // unit: seconds as type (double)
		}
		fclose(f);
	}

	/* Info 3:
	 *
	 * Kernel release `uname -r` of the machine the agent is running on.
	 */

	struct utsname uts;
	uname(&uts);
	snprintf(agent_info->uname_r, sizeof(agent_info->uname_r), "%s", uts.release);
}

int32_t scap_linux_init_platform(struct scap_platform* platform, char* lasterr, struct scap_engine_handle engine, struct scap_open_args* oargs)
{
	int rc;
	struct scap_linux_platform* linux_platform = (struct scap_linux_platform*)platform;
	linux_platform->m_lasterr = lasterr;

	linux_platform->m_engine = engine;

	linux_platform->m_proc_scan_timeout_ms = oargs->proc_scan_timeout_ms;
	linux_platform->m_proc_scan_log_interval_ms = oargs->proc_scan_log_interval_ms;
	linux_platform->m_debug_log_fn = oargs->debug_log_fn;

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

	scap_linux_retrieve_agent_info(&platform->m_agent_info);

	return SCAP_SUCCESS;
}

static const struct scap_platform_vtable scap_linux_platform = {
	.init_platform = scap_linux_init_platform,
	.refresh_addr_list = scap_linux_create_iflist,
	.get_device_by_mount_id = scap_linux_get_device_by_mount_id,
	.get_proc = scap_linux_proc_get,
	.refresh_proc_table = scap_linux_refresh_proc_table,
	.is_thread_alive = scap_linux_is_thread_alive,
	.get_global_pid = scap_linux_getpid_global,
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

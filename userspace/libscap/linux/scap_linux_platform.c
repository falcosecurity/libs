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
#include <sys/times.h>
#include <unistd.h>
#include <math.h>

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

static void scap_linux_get_rss_vsz_pss_total_memory_and_open_fds(uint32_t *rss, uint32_t *vsz, uint32_t *pss, uint64_t *host_memory_used, uint64_t *host_open_fds)
{
	FILE* f;
	char filepath[512];
	char line[512];

	/*
	 * Get memory usage of the agent itself (referred to as calling process meaning /proc/self/)
	*/

	//  No need for scap_get_host_root since we look at the agents' own process, accessible from it's own pid namespace (if applicable)
	f = fopen("/proc/self/status", "r");
	if(!f)
	{
		return;
	}

	while(fgets(line, sizeof(line), f) != NULL)
	{
		if(strncmp(line, "VmSize:", 7) == 0)
		{
			sscanf(line, "VmSize: %" SCNu32, vsz);		/* memory size returned in kb */
		}
		else if(strncmp(line, "VmRSS:", 6) == 0)
		{
			sscanf(line, "VmRSS: %" SCNu32, rss);		/* memory size returned in kb */
		}
	}
	fclose(f);

	//  No need for scap_get_host_root since we look at the agents' own process, accessible from it's own pid namespace (if applicable)
	f = fopen("/proc/self/smaps_rollup", "r");
	if(!f)
	{
		return;
	}

	while(fgets(line, sizeof(line), f) != NULL)
	{
		if(strncmp(line, "Pss:", 4) == 0)
		{
			sscanf(line, "Pss: %" SCNu32, pss);		/* memory size returned in kb */
			break;
		}
	}
	fclose(f);

	/*
	 * Get total host memory usage
	*/

	// Using scap_get_host_root since we look at the memory usage of the underlying host
	snprintf(filepath, sizeof(filepath), "%s/proc/meminfo", scap_get_host_root());
	f = fopen(filepath, "r");
	if(!f)
	{
		return;
	}

	uint64_t mem_total, mem_free, mem_buff, mem_cache = 0;

	while(fgets(line, sizeof(line), f) != NULL)
	{
		if(strncmp(line, "MemTotal:", 9) == 0)
		{
			sscanf(line, "MemTotal: %" SCNu64, &mem_total);		/* memory size returned in kb */
		}
		else if(strncmp(line, "MemFree:", 8) == 0)
		{
			sscanf(line, "MemFree: %" SCNu64, &mem_free);		/* memory size returned in kb */
		}
		else if(strncmp(line, "Buffers:", 8) == 0)
		{
			sscanf(line, "Buffers: %" SCNu64, &mem_buff);		/* memory size returned in kb */
		}
		else if(strncmp(line, "Cached:", 7) == 0)
		{
			sscanf(line, "Cached: %" SCNu64, &mem_cache);		/* memory size returned in kb */
		}
	}
	fclose(f);
	*host_memory_used = mem_total - mem_free - mem_buff - mem_cache;

	/*
	 * Get total number of allocated file descriptors (not all open files!)
	 * File descriptor is a data structure used by a program to get a handle on a file
	*/

	// Using scap_get_host_root since we look at the total open fds of the underlying host
	snprintf(filepath, sizeof(filepath), "%s/proc/sys/fs/file-nr", scap_get_host_root());
	f = fopen(filepath, "r");
	if(!f)
	{
		return;
	}
	int matched_fds = fscanf(f, "%" SCNu64, host_open_fds);
	fclose(f);

	if (matched_fds != 1) {
		return;
	}
}

static void scap_linux_get_cpu_usage_and_total_procs(double start_time, double *cpu_usage_perc, double *host_cpu_usage_perc, uint32_t *host_procs_running)
{
	FILE* f;
	char filepath[512];
	char line[512];

	struct tms time;
	if (times (&time) == (clock_t) -1)
	{
		return;
	}

	/* Number of clock ticks per second, often referred to as USER_HZ / jiffies. */
	long hz = 100;
#ifdef _SC_CLK_TCK
	if ((hz = sysconf(_SC_CLK_TCK)) < 0)
	{
		hz = 100;
	}
#endif
	/* Current uptime of the host machine in seconds.
	 * /proc/uptime offers higher precision w/ 2 decimals.
	 */

	// Using scap_get_host_root since we look at the uptime of the underlying host
	snprintf(filepath, sizeof(filepath), "%s/proc/uptime", scap_get_host_root());
	f = fopen(filepath, "r");
	if(!f)
	{
		return;
	}

	double machine_uptime_sec = 0;
	int matched_uptime = fscanf(f, "%lf", &machine_uptime_sec);
	fclose(f);

	if (matched_uptime != 1) {
		return;
	}

	/*
	 * Get CPU usage of the agent itself (referred to as calling process meaning /proc/self/)
	*/

	/* Current utime is amount of processor time in user mode of calling process. Convert to seconds. */
	double user_sec = (double)time.tms_utime / hz;

	/* Current stime is amount of time the calling process has been scheduled in kernel mode. Convert to seconds. */
	double system_sec = (double)time.tms_stime / hz;


	/* CPU usage as percentage is computed by dividing the time the process uses the CPU by the
	 * currently elapsed time of the calling process. Compare to `ps` linux util. */
	double elapsed_sec = machine_uptime_sec - start_time;
	if (elapsed_sec > 0)
	{
		*cpu_usage_perc = (double)100.0 * (user_sec + system_sec) / elapsed_sec;
		*cpu_usage_perc = round(*cpu_usage_perc * 10.0) / 10.0; // round to 1 decimal
	}

	/*
	 * Get total host CPU usage (all CPUs) as percentage and retrieve number of procs currently running.
	*/

	// Using scap_get_host_root since we look at the total CPU usage of the underlying host
	snprintf(filepath, sizeof(filepath), "%s/proc/stat", scap_get_host_root());
	f = fopen(filepath, "r");
	if(!f)
	{
		return;
	}

	/* Need only first 7 columns of /proc/stat cpu line */
	uint64_t user, nice, system, idle, iowait, irq, softirq = 0;
	while(fgets(line, sizeof(line), f) != NULL)
	{
		if(strncmp(line, "cpu ", 4) == 0)
		{
			/* Always first line in /proc/stat file, unit: jiffies */
			sscanf(line, "cpu %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64, &user, &nice, &system, &idle, &iowait, &irq, &softirq);
		}
		else if(strncmp(line, "procs_running ", 14) == 0)
		{
			sscanf(line, "procs_running %" SCNu32, host_procs_running);
			break;
		}
	}
	fclose(f);
	uint64_t sum = user + nice + system + idle + iowait + irq + softirq;
	if (sum > 0)
	{
		*host_cpu_usage_perc = 100.0 - ((idle * 100.0) / sum);
		*host_cpu_usage_perc = round(*host_cpu_usage_perc * 10.0) / 10.0; // round to 1 decimal
	}
}

static void scap_linux_get_container_memory_used(uint64_t *container_memory_used)
{
	/* In Kubernetes `container_memory_working_set_bytes` is the memory measure the OOM killer uses
	 * and values from `/sys/fs/cgroup/memory/memory.usage_in_bytes` are close enough.
	 *
	 * Please note that `kubectl top pod` numbers would reflect the sum of containers in a pod and
	 * typically libs clients (e.g. Falco) pods contain sidekick containers that use memory as well.
	 * This metric accounts only for the container with the security monitoring agent running.
	*/
	const char* filepath = getenv(SCAP_AGENT_CGROUP_MEM_PATH_ENV_VAR);
	if (filepath == NULL)
	{
		// No need for scap_get_host_root since we look at the container pid namespace (if applicable)
		// Known collision for VM memory usage, but this default value is configurable
		filepath = "/sys/fs/cgroup/memory/memory.usage_in_bytes";
	}

	FILE* f = fopen(filepath, "r");
	if(!f)
	{
		return;
	}

	/* memory size returned in bytes */
	int fscanf_matched = fscanf(f, "%" SCNu64, container_memory_used);
	if (fscanf_matched != 1)
	{
		*container_memory_used = 0;
	}

	fclose(f);

	return;
}

struct scap_metrics_vtable scap_linux_metrics_vtable = {
	.get_rss_vsz_pss_total_memory_and_open_fds = scap_linux_get_rss_vsz_pss_total_memory_and_open_fds,
	.get_cpu_usage_and_total_procs = scap_linux_get_cpu_usage_and_total_procs,
	.get_container_memory_used = scap_linux_get_container_memory_used,
};

struct scap_platform* scap_linux_alloc_platform(proc_entry_callback proc_callback, void* proc_callback_context)
{
	struct scap_linux_platform* platform = calloc(1, sizeof(*platform));

	if(platform == NULL)
	{
		return NULL;
	}

	struct scap_platform* generic = &platform->m_generic;
	generic->m_vtable = &scap_linux_platform_vtable;
	generic->m_metrics_vtable = &scap_linux_metrics_vtable;

	init_proclist(&generic->m_proclist, proc_callback, proc_callback_context);

	return generic;
}

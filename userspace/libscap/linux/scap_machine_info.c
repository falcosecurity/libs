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

#include <libscap/scap_machine_info.h>
#include <libscap/linux/scap_linux_int.h>
#include <libscap/scap_limits.h>
#include <libscap/scap_assert.h>
#include <libscap/scap.h>

#include <stdbool.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>

#define SECOND_TO_NS 1000000000ULL

void scap_os_get_agent_info(scap_agent_info* agent_info)
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
		agent_info->start_ts_epoch = st.st_ctim.tv_sec * SECOND_TO_NS + st.st_ctim.tv_nsec;
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

static uint64_t scap_linux_get_host_boot_time_ns(char* last_err)
{
	uint64_t btime = 0;
	char proc_stat[SCAP_MAX_PATH_SIZE];
	char line[512];

	/* Get boot time from btime value in /proc/stat
	 * ref: https://github.com/falcosecurity/libs/issues/932
	 * /proc/uptime and btime in /proc/stat are fed by the same kernel sources.
	 *
	 * Multiple ways to get boot time:
	 *	btime in /proc/stat
	 *	calculation via clock_gettime(CLOCK_REALTIME - CLOCK_BOOTTIME)
	 *	calculation via time(NULL) - sysinfo().uptime
	 *
	 * Maintainers preferred btime in /proc/stat because:
	 *	value does not depend on calculation using current timestamp
	 *	btime is "static" and doesn't change once set
	 *	btime is available in kernels from 2008
	 *	CLOCK_BOOTTIME is available in kernels from 2011 (2.6.38
	 *
	 * By scraping btime from /proc/stat,
	 * it is both the heaviest and most likely to succeed
	 */
	snprintf(proc_stat, sizeof(proc_stat), "%s/proc/stat", scap_get_host_root());
	FILE* f = fopen(proc_stat, "r");
	if (f == NULL)
	{
		return 0;
	}

	while(fgets(line, sizeof(line), f) != NULL)
	{
		if(sscanf(line, "btime %" PRIu64, &btime) == 1)
		{
			fclose(f);
			return btime * SECOND_TO_NS;
		}
	}
	fclose(f);
	return 0;
}

static void scap_gethostname(char* buf, size_t size)
{
	char *env_hostname = getenv(SCAP_HOSTNAME_ENV_VAR);
	if(env_hostname != NULL)
	{
		snprintf(buf, size, "%s", env_hostname);
	}
	else
	{
		gethostname(buf, size);
	}
}

int32_t scap_os_get_machine_info(scap_machine_info* machine_info, char* lasterr)
{
	// Check that we can read under '/proc'.
	// A wrong usage of the env variable 'HOST_ROOT' can be detected here.
	char filename[SCAP_MAX_PATH_SIZE] = {0};
	if(snprintf(filename, sizeof(filename), "%s/proc/", scap_get_host_root()) < 0)
	{
		if(lasterr != NULL)
		{
			snprintf(lasterr, SCAP_LASTERR_SIZE, "unable to build the `/proc` path with 'snprintf'\n");
		}
		return SCAP_FAILURE;
	}

	struct stat targetstat = {0};
	if(stat(filename, &targetstat) != 0)
	{
		if(lasterr != NULL)
		{
			snprintf(lasterr, SCAP_LASTERR_SIZE, "the directory '%s' doesn't exist on the system. Check the usage of the 'HOST_ROOT' env variable.", filename);
		}
		return SCAP_FAILURE;
	}

	machine_info->num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	machine_info->memory_size_bytes = (uint64_t)sysconf(_SC_PHYS_PAGES) * sysconf(_SC_PAGESIZE);
	scap_gethostname(machine_info->hostname, sizeof(machine_info->hostname));
	machine_info->boot_ts_epoch = scap_linux_get_host_boot_time_ns(lasterr);
	if(machine_info->boot_ts_epoch == 0)
	{
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

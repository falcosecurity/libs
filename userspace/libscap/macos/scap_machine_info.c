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

#include "scap_machine_info.h"
#include "scap_os_machine_info.h"
#include "scap_limits.h"
#include "scap_assert.h"
#include "scap.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#define US_TO_NS 1000ULL

// https://stackoverflow.com/questions/3269321/osx-programmatically-get-uptime
static uint64_t scap_macos_get_host_boot_time_ns()
{
	struct timeval boottime;
	size_t len = sizeof(boottime);
	int mib[2] = { CTL_KERN, KERN_BOOTTIME };
	if(sysctl(mib, 2, &boottime, &len, NULL, 0) < 0)
	{
		return 0;
	}

	return (boottime.tv_sec * SECOND_TO_NS) +
	       (boottime.tv_usec * US_TO_NS);
}

void scap_os_get_agent_info(scap_agent_info* agent_info)
{
	agent_info->start_ts_epoch = 0;
	agent_info->start_time = 0;

	/* Info 1:
	 *
	 * unix time in nsec of our startup time
	 */
	{
		// https://stackoverflow.com/questions/31603885/get-process-creation-date-time-in-osx-with-c-c/31605649
		struct kinfo_proc info;
		int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, (int)getpid() };
		size_t len = sizeof info;
		memset(&info, 0, len);
		int rc = sysctl(mib, 4, &info, &len, NULL, 0);
		if(rc == 0)
		{
			struct timeval tv = info.kp_proc.p_starttime;
			if(tv.tv_sec != 0)
			{
				agent_info->start_ts_epoch = (tv.tv_sec * SECOND_TO_NS) +
							     (tv.tv_usec * US_TO_NS);
			}
		}
	}

	/* Info 2:
	 *
	 * our startup time in seconds since boot
	 */
	if(agent_info->start_ts_epoch != 0)
	{
		uint64_t boot_time_ns = scap_macos_get_host_boot_time_ns();
		agent_info->start_time = (agent_info->start_ts_epoch - boot_time_ns) / (1.0 * SECOND_TO_NS);
	}

	/* Info 3:
	 *
	 * Kernel release `uname -r` of the machine the agent is running on.
	 */

	struct utsname uts;
	uname(&uts);
	snprintf(agent_info->uname_r, sizeof(agent_info->uname_r), "%s", uts.release);
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
	machine_info->num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	machine_info->memory_size_bytes = (uint64_t)sysconf(_SC_PHYS_PAGES) * sysconf(_SC_PAGESIZE);
	scap_gethostname(machine_info->hostname, sizeof(machine_info->hostname));
	machine_info->boot_ts_epoch = scap_macos_get_host_boot_time_ns();
	if(machine_info->boot_ts_epoch == 0)
	{
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}


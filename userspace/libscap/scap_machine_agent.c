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
#ifdef __linux__
#include <unistd.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#endif // __linux__

#include "scap.h"
#include "scap-int.h"

#define SECOND_TO_NS 1000000000

#ifdef __linux__
static void scap_get_bpf_stats_enabled(scap_machine_info* machine_info)
{
	machine_info->flags &= ~PPM_BPF_STATS_ENABLED;
	FILE* f;
	if((f = fopen("/proc/sys/kernel/bpf_stats_enabled", "r")))
	{
		uint32_t bpf_stats_enabled = 0;
		if(fscanf(f, "%u", &bpf_stats_enabled) == 1) {
			if (bpf_stats_enabled != 0)
			{
				machine_info->flags |= PPM_BPF_STATS_ENABLED;
			}
		}
		fclose(f);
	}
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
#endif

void scap_retrieve_machine_info(scap_machine_info* machine_info, uint64_t boot_time)
{
	machine_info->num_cpus = 0;
	machine_info->memory_size_bytes = 0;
	machine_info->reserved3 = 0;
	machine_info->reserved4 = 0;
#ifdef __linux__
	machine_info->num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	machine_info->memory_size_bytes = (uint64_t)sysconf(_SC_PHYS_PAGES) * sysconf(_SC_PAGESIZE);
	scap_gethostname(machine_info->hostname, sizeof(machine_info->hostname));
	machine_info->boot_ts_epoch = boot_time;
	scap_get_bpf_stats_enabled(machine_info);
#endif
}
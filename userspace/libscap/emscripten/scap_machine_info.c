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

#include "gettimeofday.h"
#include <sys/utsname.h>
#include <stdio.h>
#include <unistd.h>

// note: in a webassembly module we have no notion of process or host from which
// retrieving the boot time. As such, we just take a timestamp at which the
// module is inited throgh a function noted as __attribute__((constructor)), which
// should be supported by clang (emscripten's backend). We make no distiction
// between the agent's boot time and the host boot time here.
static uint64_t s_emscripten_boot_time_ns = 0;

static void retrieve_boot_time_ns() __attribute__((constructor));

static void retrieve_boot_time_ns()
{
	s_emscripten_boot_time_ns = get_timestamp_ns();
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
		// todo: this needs to be the process startup time
		agent_info->start_ts_epoch = s_emscripten_boot_time_ns;
	}

	/* Info 2:
	 *
	 * our startup time in seconds since boot
	 */
	if(agent_info->start_ts_epoch != 0)
	{
		uint64_t boot_time_ns = s_emscripten_boot_time_ns;
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
	machine_info->boot_ts_epoch = s_emscripten_boot_time_ns;
	if(machine_info->boot_ts_epoch == 0)
	{
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

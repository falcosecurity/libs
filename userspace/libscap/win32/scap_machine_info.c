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

#ifndef _UNICODE
#define _UNICODE
#endif

#include "scap_machine_info.h"
#include "scap_os_machine_info.h"
#include "scap_limits.h"
#include "scap_assert.h"
#include "scap.h"
#include "gettimeofday.h"

#include <stdbool.h>
#include <stdio.h>
#include <windows.h>
#include <tchar.h>

#define MSEC_TO_NS 1000000

typedef LONG (WINAPI * RtlGetVersionProc) (OSVERSIONINFOEX *);
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS 0
#endif

// https://stackoverflow.com/questions/10853985/programmatically-getting-system-boot-up-time-in-c-windows
static uint64_t scap_windows_get_host_boot_time_ns()
{
	return GetTickCount64() * MSEC_TO_NS;
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
		FILETIME creation_time, exit_time, kernel_time, user_time;
		if(GetProcessTimes(GetCurrentProcess(), &creation_time, &exit_time, &kernel_time, &user_time))
		{
			agent_info->start_ts_epoch = ft_to_epoch_nsec(&creation_time);
		}
	}

	/* Info 2:
	 *
	 * our startup time in seconds since boot
	 */
	if(agent_info->start_ts_epoch != 0)
	{
		uint64_t boot_time_ns = scap_windows_get_host_boot_time_ns();
		agent_info->start_time = (agent_info->start_ts_epoch - boot_time_ns) / (1.0 * SECOND_TO_NS);
	}

	/* Info 3:
	 *
	 * Kernel release `uname -r` of the machine the agent is running on.
	 */
	{
		OSVERSIONINFOEX win_version_info = {0};
		RtlGetVersionProc RtlGetVersionP = 0;
		LONG version_status = -1; // Any nonzero value should work.

		/*
		 * We want the major and minor Windows version along with other
		 * information. GetVersionEx provides this, but is deprecated.
		 * We use RtlGetVersion instead, which requires a bit of extra
		 * effort.
		 */

		HMODULE ntdll_module = LoadLibrary(_T("ntdll.dll"));
		if(ntdll_module)
		{
			RtlGetVersionP = (RtlGetVersionProc) GetProcAddress(ntdll_module, "RtlGetVersion");
			win_version_info.dwOSVersionInfoSize = sizeof(win_version_info);
			version_status = RtlGetVersionP(&win_version_info);
			FreeLibrary(ntdll_module);
		}

		if (version_status != STATUS_SUCCESS)
		{
			snprintf(agent_info->uname_r, sizeof(agent_info->uname_r), "Windows (unknown version)");
		}
		else
		{
			// more space than the absolute worst case of UTF16->UTF8 conversion
			char utf8_servicepack[sizeof(win_version_info.szCSDVersion) * 2] = {0};

			// ... but if it still gets truncated, be sad for a while and move on
			// (our output buffer is finite, anyway)
			WideCharToMultiByte(CP_UTF8, 0, win_version_info.szCSDVersion, -1, utf8_servicepack, sizeof(utf8_servicepack), NULL, NULL);

			snprintf(agent_info->uname_r, sizeof(agent_info->uname_r), "Windows %lu.%lu%s%s, build %lu",
				 win_version_info.dwMajorVersion, win_version_info.dwMinorVersion,
				 utf8_servicepack[0] != '\0' ? " " : "",
				 utf8_servicepack,
				 win_version_info.dwBuildNumber);
		}
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

int32_t scap_os_get_machine_info(scap_machine_info* machine_info, char* lasterr)
{
	SYSTEM_INFO si;
	GetSystemInfo(&si);
	machine_info->num_cpus = si.dwNumberOfProcessors;

	ULONGLONG mem_kb;
	GetPhysicallyInstalledSystemMemory(&mem_kb);
	machine_info->memory_size_bytes = mem_kb * 1024;

	scap_gethostname(machine_info->hostname, sizeof(machine_info->hostname));
	machine_info->boot_ts_epoch = scap_windows_get_host_boot_time_ns();
	if(machine_info->boot_ts_epoch == 0)
	{
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

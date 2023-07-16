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

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

//
// The following stuff is byte aligned because we save it to disk.
//
#if defined _MSC_VER
#pragma pack(push)
#pragma pack(1)
#else
#pragma pack(push, 1)
#endif

/*!
  \brief Machine information
*/
typedef struct _scap_machine_info
{
	uint32_t num_cpus;	///< Number of processors
	uint64_t memory_size_bytes; ///< Physical memory size
	uint64_t max_pid; ///< Highest PID number on this machine
	char hostname[128]; ///< The machine hostname
	uint64_t boot_ts_epoch; ///< Host boot ts in nanoseconds (epoch)
	uint64_t flags; ///< flags
	uint64_t reserved3; ///< reserved for future use
	uint64_t reserved4; ///< reserved for future use, note: because of scap file captures needs to remain uint64_t, use flags if possible
}scap_machine_info;

#pragma pack(pop)

/*!
  \brief Agent information, not intended for scap file use
*/
typedef struct _scap_agent_info
{
	uint64_t start_ts_epoch; ///< Agent start timestamp, stat /proc/self/cmdline approach, unit: epoch in nanoseconds
	double start_time; ///< /proc/self/stat start_time divided by HZ, unit: seconds since boot
	char uname_r[128]; ///< Kernel release `uname -r`
} scap_agent_info;

#ifdef __cplusplus
}
#endif

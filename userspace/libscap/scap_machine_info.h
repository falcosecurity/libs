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

/*!
  \brief Agent information, not intended for scap file use
*/
typedef struct _scap_agent_info
{
	uint64_t start_ts_epoch; ///< Agent start timestamp, stat /proc/self/cmdline approach, unit: epoch in nanoseconds
	double start_time; ///< /proc/self/stat start_time divided by HZ, unit: seconds
	char uname_r[128]; ///< Kernel release `uname -r`
} scap_agent_info;

#ifdef __cplusplus
}
#endif

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

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <libscap/scap_cgroup_set.h>

#define FOR_EACH_SUBSYS(cgset, subsys) for(                                       \
	const char *subsys = (cgset)->path, *_end = (cgset)->path + (cgset)->len; \
	subsys < _end;                                                            \
	subsys += strlen(subsys) + 1)

#ifdef __cplusplus
extern "C"
{
#endif
	struct scap_cgroup_cache;
	struct scap_threadinfo;

	struct scap_cgroup_interface
	{
		// cgroup subsystems available for v1 and v2
		struct scap_cgroup_set m_subsystems_v1;
		struct scap_cgroup_set m_subsystems_v2;

		// cgroupfs mount points
		struct scap_cgroup_set m_mounts_v1;
		char m_mount_v2[SCAP_MAX_PATH_SIZE];

		bool m_use_cache;
		struct scap_cgroup_cache* m_cache;

		// the cgroups of the current process, as seen from the host cgroupns
		// empty if:
		// - we're not running in a cgroupns
		// - we can't escape the cgroupns
		// - the `scap_cgroup_interface` was created `with_self_cg=false`
		struct scap_cgroup_set m_self_v1;
		char m_self_v2[SCAP_MAX_PATH_SIZE];
	};

	int32_t scap_cgroup_interface_init(struct scap_cgroup_interface* cgi, const char* host_root, char* error, bool with_self_cg);

	int32_t scap_cgroup_get_thread(struct scap_cgroup_interface* cgi, const char* procdirname, struct scap_cgroup_set* cg, char* error);

	const char* scap_cgroup_get_subsys_mount(const struct scap_cgroup_interface* cgi, const char* subsys, int* version);

	void scap_cgroup_enable_cache(struct scap_cgroup_interface* cgi);

	void scap_cgroup_clear_cache(struct scap_cgroup_interface* cgi);
#ifdef __cplusplus
};
#endif

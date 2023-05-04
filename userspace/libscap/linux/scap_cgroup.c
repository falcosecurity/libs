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

#include "scap_cgroup.h"

#include "scap_assert.h"
#include "scap.h"
#include "strerror.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

int32_t scap_proc_fill_cgroups(char* error, int cgroup_version, struct scap_threadinfo* tinfo, const char* procdirname)
{
	char filename[SCAP_MAX_PATH_SIZE];
	char line[SCAP_MAX_CGROUPS_SIZE];

	tinfo->cgroups_len = 0;
	snprintf(filename, sizeof(filename), "%scgroup", procdirname);

	FILE* f = fopen(filename, "r");
	if(f == NULL)
	{
		if(errno == ENOENT || errno == EACCES)
		{
			return SCAP_SUCCESS;
		}

		ASSERT(false);
		return scap_errprintf(error, errno, "open cgroup file %s failed", filename);
	}

	while(fgets(line, sizeof(line), f) != NULL)
	{
		char* token;
		char* subsys_list;
		char* cgroup;
		char* scratch;
		// Default subsys list for cgroups v2 unified hierarchy.
		// These are the ones we actually use in cri container engine.
		char default_subsys_list[] = "cpu,memory,cpuset";

		// id
		token = strtok_r(line, ":", &scratch);
		if(token == NULL)
		{
			ASSERT(false);
			fclose(f);
			return scap_errprintf(error, 0, "Did not find id in cgroup file %s", filename);
		}

		// subsys
		subsys_list = strtok_r(NULL, ":", &scratch);
		if(subsys_list == NULL)
		{
			ASSERT(false);
			fclose(f);
			return scap_errprintf(error, 0, "Did not find subsys in cgroup file %s", filename);
		}

		// Hack to detect empty fields, because strtok does not support it
		// strsep() should be used to fix this but it's not available
		// on CentOS 6 (has been added from Glibc 2.19)
		if(subsys_list - token - strlen(token) > 1)
		{
			// Subsys list empty (ie: it contains cgroup path instead)!
			//
			// See https://man7.org/linux/man-pages/man7/cgroups.7.html:
			// 5:cpuacct,cpu,cpuset:/daemons
			//
			//              The colon-separated fields are, from left to right:
			//
			//              1. For cgroups version 1 hierarchies, this field contains
			//                 a unique hierarchy ID number that can be matched to a
			//                 hierarchy ID in /proc/cgroups.  For the cgroups version
			//                 2 hierarchy, this field contains the value 0.
			//
			//              2. For cgroups version 1 hierarchies, this field contains
			//                 a comma-separated list of the controllers bound to the
			//                 hierarchy.  For the cgroups version 2 hierarchy, this
			//                 field is empty.
			//
			//              3. This field contains the pathname of the control group
			//                 in the hierarchy to which the process belongs.  This
			//                 pathname is relative to the mount point of the
			//                 hierarchy.
			//
			// -> for cgroup2: id is always 0 and subsys list is always empty (single unified hierarchy)
			// -> for cgroup1: skip subsys empty because it means controller is not mounted on any hierarchy
			if(cgroup_version == 2 && strcmp(token, "0") == 0)
			{
				cgroup = subsys_list;
				subsys_list = default_subsys_list; // force-set a default subsys list

				size_t cgroup_len = strlen(cgroup);
				if(cgroup_len != 0 && cgroup[cgroup_len - 1] == '\n')
				{
					cgroup[cgroup_len - 1] = '\0';
				}
			}
			else
			{
				// skip cgroups like this:
				// 0::/init.scope
				continue;
			}
		}
		else
		{
			// cgroup should be the only thing remaining so use newline as the delimiter.
			cgroup = strtok_r(NULL, "\n", &scratch);
			if(cgroup == NULL)
			{
				ASSERT(false);
				fclose(f);
				return scap_errprintf(error, 0, "Did not find cgroup in cgroup file %s", filename);
			}
		}

		while((token = strtok_r(subsys_list, ",", &scratch)) != NULL)
		{
			subsys_list = NULL;
			if(strlen(cgroup) + 1 + strlen(token) + 1 > SCAP_MAX_CGROUPS_SIZE - tinfo->cgroups_len)
			{
				ASSERT(false);
				fclose(f);
				return SCAP_SUCCESS;
			}

			snprintf(tinfo->cgroups + tinfo->cgroups_len, SCAP_MAX_CGROUPS_SIZE - tinfo->cgroups_len, "%s=%s", token, cgroup);
			tinfo->cgroups_len += strlen(cgroup) + 1 + strlen(token) + 1;
		}
	}

	fclose(f);
	return SCAP_SUCCESS;
}

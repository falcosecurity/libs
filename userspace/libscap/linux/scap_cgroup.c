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
#include "uthash.h"

#include <errno.h>
#include <mntent.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

struct scap_cgroup_cache
{
	char path[SCAP_MAX_PATH_SIZE];
	struct scap_cgroup_set subsystems;

	UT_hash_handle hh;
};

static int32_t __attribute__((format(printf, 2, 3)))
scap_cgroup_printf(struct scap_cgroup_set* cgset, const char* fmt, ...)
{
	va_list va;

	int max_space = SCAP_MAX_CGROUPS_SIZE - cgset->len;
	if(max_space <= 0)
	{
		// no room in the buffer
		return SCAP_FAILURE;
	}

	va_start(va, fmt);
	int nwritten = vsnprintf(cgset->path + cgset->len, max_space, fmt, va);
	va_end(va);

	if(nwritten > max_space)
	{
		// output truncated
		return SCAP_FAILURE;
	}

	cgset->len += nwritten + 1;
	return SCAP_SUCCESS;
}

// Get all the v1 subsystems out of /proc/self/cgroup
//
// Given the sample content below:
//
// 12:devices:/user.slice
// 11:rdma:/
// 10:freezer:/
// 9:blkio:/
// 8:pids:/user.slice/user-0.slice/session-13542.scope
// 7:net_cls,net_prio:/
// 6:perf_event:/
// 5:hugetlb:/
// 4:memory:/
// 3:cpu,cpuacct:/user.slice/user-0.slice/session-13542.scope
// 2:cpuset:/
// 1:name=systemd:/user.slice/user-0.slice/session-13542.scope
// 0::/user.slice/user-0.slice/session-13542.scope
//
// we want to `scap_cgroup_printf()` the subsystem names into `subsystems`:
// - devices
// - rdma
// - freezer
// - blkio
// - pids
// - net_cls (note this is mounted together with the following one)
// - net_prio
// - perf_event
// - hugetlb
// - memory
// - cpu
// - cpuacct
// - cpuset
// - name=systemd
//
// (we skip the empty one since it's either v2, or an empty subsys list without a name, i.e. generally useless)
static int32_t get_cgroup_subsystems_v1(struct scap_cgroup_set* subsystems)
{
	char line[SCAP_MAX_PATH_SIZE];
	subsystems->len = 0;

	FILE* cgroups = fopen("/proc/self/cgroup", "r");
	if(!cgroups)
	{
		return SCAP_FAILURE;
	}

	while(fgets(line, sizeof(line), cgroups) != NULL)
	{
		// 3:cpu,cpuacct:/user.slice/user-0.slice/session-13542.scope
		//  ^p
		char* p = strchr(line, ':');
		if(!p)
		{
			fclose(cgroups);
			return SCAP_FAILURE;
		}
		// 3:cpu,cpuacct:/user.slice/user-0.slice/session-13542.scope
		//  ^p          ^q
		char* q = strchr(p, ':');
		if(!q)
		{
			fclose(cgroups);
			return SCAP_FAILURE;
		}

		// 3:cpu,cpuacct
		//  ^p          ^q
		*q = 0;
		if(strlen(p) == 0)
		{
			continue;
		}

		while(1)
		{
			// 3:cpu\0cpuacct
			//  ^p  ^q
			char* comma = strchr(p, ',');
			if(comma)
			{
				*comma = 0;
			}

			if(scap_cgroup_printf(subsystems, "%s", p) == SCAP_FAILURE)
			{
				fclose(cgroups);
				return SCAP_FAILURE;
			}

			if(!comma)
			{
				break;
			}

			// 3:cpu\0cpuacct
			//        ^p
			p = comma + 1;
		}
	}

	fclose(cgroups);
	return SCAP_SUCCESS;
}

// Get mount points for all cgroup v1 subsystems
//
// Note: some v1 subsystems can be mounted together (e.g. cpu,cpuacct): we don't care and remember them separately
// This needs to be called for each mount entry when looping over `getmntent_r`
//
// To bypass cgroup namespaces, we always access the host's cgroup filesystem via /proc/1/root/
static int32_t scap_get_cgroup_mount_v1(struct mntent* de, struct scap_cgroup_set* mounts, struct scap_cgroup_set* cg_subsystems, const char* host_root, char* error)
{
	if(cg_subsystems->len == 0 && get_cgroup_subsystems_v1(cg_subsystems) == SCAP_FAILURE)
	{
		return scap_errprintf(error, 0, "failed to parse /proc/self/cgroup");
	}

	FOR_EACH_SUBSYS(cg_subsystems, cg_subsys)
	{
		// hasmntopt is smart enough to match comma-delimited strings, so e.g.
		// "cpuset,cpuacct" won't match "cpu" but "cpu,cpuacct" will
		if(!hasmntopt(de, cg_subsys))
		{
			continue;
		}

		if(scap_cgroup_printf(mounts, "%s=%s/proc/1/root%s", cg_subsys, host_root, de->mnt_dir) != SCAP_SUCCESS)
		{
			ASSERT(false);
			return SCAP_FAILURE;
		}
	}

	return SCAP_SUCCESS;
}

// Get all subsystem names for the v2 cgroup at `cgroup_mount`
//
// This is achieved by simply reading the contents of cgroup.controllers
// in that directory (it's a single line) and splitting it across spaces.
//
// Example:
// cpuset cpu io memory hugetlb pids rdma misc
//
// Note: the controller list may also be empty (e.g. when booting with
// systemd.unified_cgroup_hierarchy=0), so we handle that case as well
//
// We need to walk up the directory tree when looking for subsystems,
// so we will end up calling this function repeatedly for the same directory.
// To minimize the overhead, we use a simple cache.
static int32_t get_cgroup_subsystems_v2(struct scap_cgroup_interface* cgi, struct scap_cgroup_set* subsystems, const char* cgroup_mount)
{
	if(cgi->m_use_cache)
	{
		struct scap_cgroup_cache* cached;
		HASH_FIND_STR(cgi->m_cache, cgroup_mount, cached);

		if(cached != NULL)
		{
			*subsystems = cached->subsystems;
			return SCAP_SUCCESS;
		}
	}

	subsystems->len = 0;

	char line[SCAP_MAX_PATH_SIZE];
	snprintf(line, sizeof(line), "%s/cgroup.controllers", cgroup_mount);
	FILE* cgroup_controllers = fopen(line, "r");
	if(!cgroup_controllers)
	{
		return SCAP_FAILURE;
	}

	if(fgets(line, sizeof(line), cgroup_controllers) == NULL)
	{
		// no subsystems, report an empty set
		line[0] = 0;
	}
	fclose(cgroup_controllers);

	// cpuset cpu io memory hugetlb pids rdma misc
	// ^p
	char* p = line;
	while(1)
	{
		// cpuset cpu io memory hugetlb pids rdma misc
		//       ^p
		size_t pos = strcspn(p, " \n");
		if(pos == 0)
		{
			break;
		}

		// cpuset\0cpu io memory hugetlb pids rdma misc
		//       ^p[pos]
		p[pos] = 0;
		if(scap_cgroup_printf(subsystems, "%s", p) == SCAP_FAILURE)
		{
			return SCAP_FAILURE;
		}

		p = p + pos + 1;
		// cpuset\0cpu io memory hugetlb pids rdma misc
		//         ^p
	}

	if(cgi->m_use_cache)
	{
		struct scap_cgroup_cache* cached = malloc(sizeof(*cached));
		if(cached)
		{
			int uth_status = SCAP_SUCCESS;
			snprintf(cached->path, sizeof(cached->path), "%s", cgroup_mount);
			memcpy(&cached->subsystems, subsystems, sizeof(cached->subsystems));

			HASH_ADD_STR(cgi->m_cache, path, cached);
			if(uth_status != SCAP_SUCCESS)
			{
				free(cached);
			}
		}
	}

	return SCAP_SUCCESS;
}

// Get the v2 cgroup mount
//
// Since there is just one, we don't need to do anything fancy here, just glue the pieces together
static int32_t scap_get_cgroup_mount_v2(struct mntent* de, char* mountpoint, const char* host_root)
{
	snprintf(mountpoint, SCAP_MAX_PATH_SIZE, "%s/proc/1/root%s", host_root, de->mnt_dir);
	return SCAP_SUCCESS;
}

int32_t scap_cgroup_interface_init(struct scap_cgroup_interface* cgi, char* error)
{
	const char* host_root = scap_get_host_root();
	char filename[SCAP_MAX_PATH_SIZE];

	cgi->m_use_cache = true;
	cgi->m_cache = NULL;
	cgi->m_subsystems_v1.len = 0;
	cgi->m_subsystems_v2.len = 0;
	cgi->m_mounts_v1.len = 0;
	cgi->m_mount_v2[0] = 0;

	snprintf(filename, sizeof(filename), "%s/proc/1/mounts", host_root);
	FILE* mounts = setmntent(filename, "r");
	if(mounts == NULL)
	{
		return scap_errprintf(error, errno, "failed to open %s", filename);
	}

	struct mntent entry, *de;
	char mntent_buf[4096];

	while((de = getmntent_r(mounts, &entry, mntent_buf, sizeof(mntent_buf))) != NULL)
	{
		if(strcmp(de->mnt_type, "cgroup") == 0)
		{
			scap_get_cgroup_mount_v1(de, &cgi->m_mounts_v1, &cgi->m_subsystems_v1, host_root, error);
		}
		else if(strcmp(de->mnt_type, "cgroup2") == 0)
		{
			scap_get_cgroup_mount_v2(de, cgi->m_mount_v2, host_root);
			get_cgroup_subsystems_v2(cgi, &cgi->m_subsystems_v2, cgi->m_mount_v2);
		}
	}

	endmntent(mounts);

	return SCAP_SUCCESS;
}

// does `subsys` exist in the `cg` set?
static bool scap_cgroup_find_subsys(const struct scap_cgroup_set* cg, const char* subsys)
{
	FOR_EACH_SUBSYS(cg, cgset_subsys)
	{
		if(strcmp(cgset_subsys, subsys) == 0)
		{
			return true;
		}
	}

	return false;
}

// does `smaller` contain all the entries in `larger`?
static bool scap_cgroup_set_contains_all(const struct scap_cgroup_set* larger, const struct scap_cgroup_set* smaller)
{
	FOR_EACH_SUBSYS(larger, cgset_subsys)
	{
		if(!scap_cgroup_find_subsys(smaller, cgset_subsys))
		{
			return false;
		}
	}

	return true;
}

// Find actual cgroups for each v2 subsystem of `cgroup`
//
// Even though cgroups v2 have a unified hierarchy (i.e. all subsystems use the same cgroup tree
// and there's just one entry in /proc/<pid>/cgroup), for example, the following tree:
//
// $ cat /proc/self/cgroup
// 0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-org.gnome.Terminal.slice/vte-spawn-5344486b-2f3a-4de3-85d7-4cab5f76db2b.scope
// $ cat /sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/app-org.gnome.Terminal.slice/vte-spawn-5344486b-2f3a-4de3-85d7-4cab5f76db2b.scope/cgroup.controllers
// memory pids
// $ cat /sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/app-org.gnome.Terminal.slice/cgroup.controllers
// memory pids
// $ cat /sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/cgroup.controllers
// memory pids
// $ cat /sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/cgroup.controllers
// memory pids
// $ cat /sys/fs/cgroup/user.slice/user-1000.slice/cgroup.controllers
// memory pids
// $ cat /sys/fs/cgroup/user.slice/cgroup.controllers
// cpuset cpu io memory pids
// $ cat /sys/fs/cgroup/cgroup.controllers
// cpuset cpu io memory hugetlb pids rdma misc
//
// is equivalent to a v1 setup of:
// 1:memory,pids:/user.slice/user-1000.slice/user@1000.service/app.slice/app-org.gnome.Terminal.slice/vte-spawn-5344486b-2f3a-4de3-85d7-4cab5f76db2b.scope
// 2:cpuset,cpu,io:/users.slice
// 3:hugetlb,rdma,misc:/
//
// To find the above cgroups, we need to walk up the directory tree, starting at the process cgroup,
// looking at cgroup.controllers at each level. For every level, we see if there are any new subsystems enabled
// and if so, add them to the cgroup set.
//
// We walk the tree upwards until we either reach the cgroup mount point, or we find all the subsystems
static int32_t scap_cgroup_resolve_v2(struct scap_cgroup_interface* cgi, const char* cgroup, struct scap_cgroup_set* cg)
{
	char full_cgroup[SCAP_MAX_PATH_SIZE];
	char cgroup_path[SCAP_MAX_PATH_SIZE];

	int nwritten = snprintf(full_cgroup, sizeof(full_cgroup), "%s", cgroup);
	if(nwritten >= sizeof(full_cgroup))
	{
		return SCAP_FAILURE;
	}

	nwritten = snprintf(cgroup_path, sizeof(cgroup_path), "%s%s", cgi->m_mount_v2, full_cgroup);
	if(nwritten >= sizeof(cgroup_path))
	{
		return SCAP_FAILURE;
	}

	struct scap_cgroup_set found_subsystems = {.len = 0};
	while(1) // not reached cgroup mountpoint yet
	{
		struct scap_cgroup_set current_subsystems;
		if(get_cgroup_subsystems_v2(cgi, &current_subsystems, cgroup_path) != SCAP_SUCCESS)
		{
			return SCAP_FAILURE;
		}

		FOR_EACH_SUBSYS(&current_subsystems, cgset_subsys)
		{
			char subsys[SCAP_MAX_PATH_SIZE];
			char* subsys_end = strchr(cgset_subsys, '=');
			ASSERT(subsys_end != NULL);
			int subsys_len = (int)(subsys_end - cgset_subsys) - 1;

			snprintf(subsys, sizeof(subsys), "%.*s", subsys_len, cgset_subsys);
			if(!scap_cgroup_find_subsys(&found_subsystems, cgset_subsys))
			{
				if(scap_cgroup_printf(cg, "%s=%s", subsys, full_cgroup) != SCAP_SUCCESS)
				{
					return SCAP_FAILURE;
				}
				if(scap_cgroup_printf(&found_subsystems, "%s", subsys) != SCAP_SUCCESS)
				{
					return SCAP_FAILURE;
				}
			}
		}

		if(full_cgroup[1] == 0) // i.e. full_cgroup is just "/"
		{
			// reached the root, bail out
			break;
		}

		if(scap_cgroup_set_contains_all(&cgi->m_subsystems_v2, &found_subsystems))
		{
			break;
		}

		char* q;

		q = strrchr(full_cgroup, '/');
		if(!q)
		{
			break;
		}
		if(q == full_cgroup)
		{
			// leave the initial '/' in
			q++;
		}
		*q = 0;

		q = strrchr(cgroup_path, '/');
		ASSERT(q);
		*q = 0;
	}
	return SCAP_SUCCESS;
}

// Get all cgroups (v1 and v2) for a thread whose /proc directory is `procdirname`
int32_t scap_cgroup_get_thread(struct scap_cgroup_interface* cgi, const char* procdirname, struct scap_cgroup_set* cg, char* error)
{
	char filename[SCAP_MAX_PATH_SIZE];
	char line[SCAP_MAX_CGROUPS_SIZE];

	cg->len = 0;
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
			if(cgi->m_mount_v2[0] != 0 && strcmp(token, "0") == 0)
			{
				cgroup = subsys_list;
				size_t cgroup_len = strlen(cgroup);
				if(cgroup_len != 0 && cgroup[cgroup_len - 1] == '\n')
				{
					cgroup[cgroup_len - 1] = '\0';
				}

				if(scap_cgroup_resolve_v2(cgi, cgroup, cg) != SCAP_SUCCESS)
				{
					fclose(f);
					return scap_errprintf(error, 0, "Cannot resolve v2 cgroups");
				}
				continue;
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
			if(scap_cgroup_printf(cg, "%s=%s", token, cgroup) != SCAP_SUCCESS)
			{
				ASSERT(false);
				fclose(f);
				return SCAP_SUCCESS;
			}
		}
	}

	fclose(f);
	return SCAP_SUCCESS;
}

// Get the mountpoint and version of a particular cgroup subsystem
//
// Note: there's no notion of a system-wide cgroup version: each subsystem can be mounted
// either as v1 or v2 (but once mounted, it stays there; you can't have a subsystem mounted
// both ways)
const char* scap_cgroup_get_subsys_mount(const struct scap_cgroup_interface* cgi, const char* subsys, int* version)
{
	size_t subsys_len = strlen(subsys);
	FOR_EACH_SUBSYS(&cgi->m_mounts_v1, cgset_subsys)
	{
		if(strncmp(cgset_subsys, subsys, subsys_len) == 0 && cgset_subsys[subsys_len] == '=')
		{
			*version = 1;
			return cgset_subsys + subsys_len + 1;
		}
	}

	if(cgi->m_mount_v2[0])
	{
		*version = 2;
		return cgi->m_mount_v2;
	}

	ASSERT(false);
	*version = 0;
	return NULL;
}

void scap_cgroup_clear_cache(struct scap_cgroup_interface* cgi)
{
	cgi->m_use_cache = false;

	if(cgi->m_cache)
	{
		struct scap_cgroup_cache* cache;
		struct scap_cgroup_cache* tcache;
		HASH_ITER(hh, cgi->m_cache, cache, tcache)
		{
			HASH_DEL(cgi->m_cache, cache);
			free(cache);
		}

		cgi->m_cache = NULL;
	}
}

void scap_cgroup_enable_cache(struct scap_cgroup_interface* cgi)
{
	scap_cgroup_clear_cache(cgi);
	cgi->m_use_cache = true;
}

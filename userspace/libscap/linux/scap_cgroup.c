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

#include <libscap/linux/scap_cgroup.h>

#include <libscap/scap_assert.h>
#include <libscap/scap_const.h>
#include <libscap/strerror.h>
#include <libscap/uthash_ext.h>

#include <dirent.h>
#include <errno.h>
#include <mntent.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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

static int32_t scap_grep_cgroups(char* path, char* path_end, const char* pid_str)
{
	char line[SCAP_MAX_PATH_SIZE];

	// we reuse the `path` buffer (containing the path to the cgroup) to store
	// the path to cgroup.procs while we're opening it
	// i.e.:
	//
	// before:
	// |/sys/fs/cgroup/foo                |
	// ^ path             ^ path_end      ^ SCAP_MAX_PATH_SIZE
	//
	// after snprintf:
	// |/sys/fs/cgroup/foo/cgroup.procs   |
	// ^ path             ^ path_end      ^ SCAP_MAX_PATH_SIZE
	//
	// after the fopen(), we reset the `path` buffer back to original:
	//
	// |/sys/fs/cgroup/foo                |
	// ^ path             ^ path_end      ^ SCAP_MAX_PATH_SIZE
	snprintf(path_end, SCAP_MAX_PATH_SIZE - (path_end - path), "/cgroup.procs");
	FILE* cg = fopen(path, "r");
	*path_end = 0;

	if(!cg)
	{
		return SCAP_FAILURE;
	}

	while(fgets(line, sizeof(line), cg) != NULL)
	{
		if(strcmp(line, pid_str) == 0)
		{
			fclose(cg);
			return SCAP_SUCCESS;
		}
	}

	fclose(cg);
	return SCAP_NOTFOUND;
}

static int32_t scap_find_my_cgroup(char* path, const char* pid_str);

// `path` is a buffer of `SCAP_MAX_PATH_SIZE` bytes, containing the full
// filesystem path to a cgroup
// `path_end` points to NUL terminator of the path (inside `path`)
// `pid_str` is the current pid, formatted as a string with a newline appended
// (this is what we're looking for in .../cgroup.procs)
static int32_t scap_cgroup_descend(char* path, char* path_end, const char* pid_str)
{
	DIR* cg;
	struct dirent* pde;
	struct stat s;

	cg = opendir(path);
	if(!cg)
	{
		return SCAP_FAILURE;
	}

	*path_end = '/';

	while(1)
	{
		// For all directories in `path`, append the directory name and call scap_find_my_cgroup
		// (which calls scap_cgroup_descend recursively if `pid_str` is not found in the directory).
		//
		// This results in a depth-first search across all cgroups.
		pde = readdir(cg);
		if(pde == NULL)
		{
			closedir(cg);
			break;
		}

		if(pde->d_name[0] == '.')
		{
			continue;
		}

		snprintf(path_end + 1, SCAP_MAX_PATH_SIZE - (path_end + 1 - path), "%s", pde->d_name);
		if(lstat(path, &s) != 0)
		{
			continue;
		}

		if(S_ISDIR(s.st_mode))
		{
			int ret = scap_find_my_cgroup(path, pid_str);
			if(ret == SCAP_SUCCESS)
			{
				closedir(cg);
				return ret;
			}
		}
	}

	// didn't find us anywhere :(
	return SCAP_FAILURE;
}

// on entry:
// - path contains the root directory to scan
// - pid_str contains the pid to find with a trailing newline (e.g. "1234\n")
// on exit:
// - if ret == SCAP_SUCCESS, path contains the full path to the cgroup found
// - otherwise, the content of path is unspecified
static int32_t scap_find_my_cgroup(char* path, const char* pid_str)
{
	int32_t ret;
	char* path_end = path + strlen(path);

	// first, try the current directory
	ret = scap_grep_cgroups(path, path_end, pid_str);
	if(ret != SCAP_NOTFOUND)
	{
		return ret;
	}

	// we failed. look for subdirectories and descend
	return scap_cgroup_descend(path, path_end, pid_str);
}

// This function superficially looks like strrchr, but it has
// an important difference: strrchr starts looking for the character
// at str+strlen(str)-1, while scan_back starts the search at
// an arbitrary point in the string
static const char* scan_back(const char* start, const char* end)
{
	const char* q = end;
	while(1)
	{
		if(*q == '/')
		{
			return q;
		}
		else if(q == start)
		{
			return NULL;
		}
		else
		{
			q--;
		}
	}
}

// Determine the absolute(ish) path of prefix+path
//
// If `path` is absolute already (doesn't start with a "/.."), just return it
// otherwise, strip all the "/.." prefixes from `path` and the corresponding number
// of subdirectories from `prefix`.
//
// The actual interesting return value is passed via `prefix_len` and `path_len`:
// - `prefix_len` indicates how many initial characters of `prefix` we should take
// - `path_strip_len` indicates how many initial characters of `path` we should skip
// with a `/` in between to get the absolute path.
//
// The end result is that the absolute path can be recreated via printf without extra
// copies of the source strings:
//
// printf(cg, "%.*s%s", (int)prefix_len, prefix, path + path_strip_len);
//
// Example:
// - on entry:
//   prefix = "foo/bar/baz/cg1/cg2"
//   path = "/../../something/else"
// - pointers involved:
//   "foo/bar/baz/cg1/cg2"
//    ^prefix            ^prefix_p
//   "/../../something/else"
//    ^path_p
// - after 1 loop:
//   "foo/bar/baz/cg1/cg2"
//    ^prefix        ^prefix_p
//   "/../../something/else"
//       ^path_p
// - after 2 loops:
//   "foo/bar/baz/cg1/cg2"
//    ^prefix    ^prefix_p
//   "/../../something/else"
//          ^path_p
//
// - output
//   "foo/bar/baz/cg1/cg2"
//    |<-------->| prefix_len
//   "/../../something/else"
//    |<-->| path_strip_len
//
// Note: we have a special case when path is just a bunch of `/../../../`s: we strip the remaining
// slash so that we don't end up with doubled slashes (one from the prefix, one from the path)
static int32_t scap_cgroup_prefix_path(const char* prefix, const char* path, size_t* prefix_len, size_t* path_strip_len)
{
	ASSERT(prefix != NULL);
	ASSERT(path != NULL);

	const char* prefix_p = prefix + strlen(prefix);
	const char* path_p = path;

	while(strncmp(path_p, "/..", 3) == 0)
	{
		// If there's a trailing slash, remove it before scanning.
		if (*prefix_p == '/' && prefix_p != prefix)
		{
			prefix_p--;
		}

		path_p += 3;
		prefix_p = scan_back(prefix, prefix_p);
		if(prefix_p == NULL)
		{
			return SCAP_FAILURE;
		}
	}

	if(!strcmp(path_p, "/"))
	{
		path_p++;
	}

	*prefix_len = prefix_p - prefix;
	*path_strip_len = path_p - path;
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
		//   ^p         ^q
		p += 1;
		char* q = strchr(p, ':');
		if(!q)
		{
			fclose(cgroups);
			return SCAP_FAILURE;
		}

		// 3:cpu,cpuacct
		//   ^p         ^q
		*q = 0;
		if(strlen(p) == 0)
		{
			continue;
		}

		while(1)
		{
			// 3:cpu\0cpuacct
			//   ^p ^q
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

// Get the (v1) cgroups of the current process, bypassing cgroup namespace restrictions
//
// We can't simply read them from /proc/self/cgroup, since these names will be relative to the cgroup
// namespace root (i.e. probably just "/"). Instead, we do a recursive grep of all cgroup.procs files
// under each mountpoint for our process id.
static int32_t scap_get_cgroup_self_v1_cgroupns(struct mntent* de, struct scap_cgroup_set* self, struct scap_cgroup_set* cg_subsystems, const char* host_root, char* pid_str, char* error)
{
	if(cg_subsystems->len == 0 && get_cgroup_subsystems_v1(cg_subsystems) == SCAP_FAILURE)
	{
		return scap_errprintf(error, 0, "failed to parse /proc/self/cgroup");
	}

	FOR_EACH_SUBSYS(cg_subsystems, cgset_subsys)
	{
		if(!hasmntopt(de, cgset_subsys))
		{
			continue;
		}

		char my_cg[SCAP_MAX_PATH_SIZE];
		snprintf(my_cg, sizeof(my_cg), "%s/proc/1/root%s", host_root, de->mnt_dir);
		char* p = my_cg + strlen(my_cg);

		if(scap_find_my_cgroup(my_cg, pid_str) != SCAP_SUCCESS)
		{
			return SCAP_FAILURE;
		}

		scap_cgroup_printf(self, "%s=%s", cgset_subsys, p);
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
		struct scap_cgroup_cache* cached = (struct scap_cgroup_cache*)malloc(sizeof(*cached));
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

// Get the (v2) cgroup of the current process, bypassing cgroup namespace restrictions
//
// We can't simply read it from /proc/self/cgroup, since the name will be relative to the cgroup
// namespace root (i.e. probably just "/"). Instead, we do a recursive grep of all cgroup.procs files
// under the v2 mountpoint for our process id.
static int32_t scap_get_cgroup_self_v2_cgroupns(struct mntent* de, char* self, const char* host_root, char* pid_str)
{
	char my_cg[SCAP_MAX_PATH_SIZE];
	size_t my_cg_len = snprintf(my_cg, sizeof(my_cg), "%s/proc/1/root%s", host_root, de->mnt_dir);
	if(my_cg_len >= sizeof(my_cg))
	{
		return SCAP_FAILURE;
	}
	if(scap_find_my_cgroup(my_cg, pid_str) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}

	snprintf(self, SCAP_MAX_PATH_SIZE, "%s", my_cg + my_cg_len);
	return SCAP_SUCCESS;
}

static bool scap_in_cgroupns(const char* host_root)
{
	// compare our cgroup ns id with init's (pid 1)
	// when running in a container, we need access to the host's /proc directory
	// for two reasons:
	// - so that /proc/1 is actually the host-wide init and not a containerized process
	// - so that we can walk through /proc/1/root and into the host's cgroup fs
	//   (in order to find the real cgroup we're in, as seen from the root cgroup ns)
	//
	// if we can't access the real root, whatever we do will give us wrong cgroup names
	// with cgroupns enabled, so it doesn't matter what we do
	// (we just pretend we're not in a cgroupns)
	char filename[SCAP_MAX_PATH_SIZE];
	char our_cgroupns[SCAP_MAX_PATH_SIZE];
	char init_cgroupns[SCAP_MAX_PATH_SIZE];
	ssize_t link_len;

	snprintf(filename, sizeof(filename), "%s/proc/self/ns/cgroup", host_root);
	link_len = readlink(filename, our_cgroupns, sizeof(our_cgroupns));
	if(link_len < 0 || link_len >= sizeof(our_cgroupns))
	{
		// < 0 means couldn't get the link; assuming cgroupns not available
		// otherwise cgroupns link is too long, which is surprising since it has a fixed,
		// fairly short length
		return false;
	}
	our_cgroupns[link_len] = 0;

	snprintf(filename, sizeof(filename), "%s/proc/1/ns/cgroup", host_root);
	link_len = readlink(filename, init_cgroupns, sizeof(init_cgroupns));
	if(link_len < 0 || link_len >= sizeof(our_cgroupns))
	{
		return false;
	}
	init_cgroupns[link_len] = 0;

	if(strcmp(init_cgroupns, our_cgroupns) == 0)
	{
		// we're in the root cgroup ns, no hacks necessary
		return false;
	}

	return true;
}

int32_t scap_cgroup_interface_init(struct scap_cgroup_interface* cgi, const char* host_root, char* error, bool with_self_cg)
{
	char filename[SCAP_MAX_PATH_SIZE];
	bool in_cgroupns = false;
	char pid_str[40];

	cgi->m_use_cache = true;
	cgi->m_cache = NULL;
	cgi->m_subsystems_v1.len = 0;
	cgi->m_subsystems_v2.len = 0;
	cgi->m_mounts_v1.len = 0;
	cgi->m_mount_v2[0] = 0;
	cgi->m_self_v1.len = 0;
	cgi->m_self_v2[0] = 0;

	// if we don't need our cgroup name (will just use the mountpoints, with the full cgroup names coming
	// from elsewhere), we can simply assume we're not in a cgroup namespace (the result is the same)
	if(with_self_cg)
	{
		in_cgroupns = scap_in_cgroupns(host_root);
	}

	if(in_cgroupns)
	{
		snprintf(pid_str, sizeof(pid_str), "%d\n", getpid());
	}

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
			if(in_cgroupns)
			{
				scap_get_cgroup_self_v1_cgroupns(de, &cgi->m_self_v1, &cgi->m_subsystems_v1, host_root, pid_str, error);
			}
		}
		else if(strcmp(de->mnt_type, "cgroup2") == 0)
		{
			scap_get_cgroup_mount_v2(de, cgi->m_mount_v2, host_root);
			get_cgroup_subsystems_v2(cgi, &cgi->m_subsystems_v2, cgi->m_mount_v2);
			if(in_cgroupns)
			{
				scap_get_cgroup_self_v2_cgroupns(de, cgi->m_self_v2, host_root, pid_str);
			}
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
	int nwritten;

	if(cgi->m_self_v2[0])
	{
		size_t prefix_len;
		size_t suffix_skip_len;
		if(scap_cgroup_prefix_path(cgi->m_self_v2, cgroup, &prefix_len, &suffix_skip_len) !=
		   SCAP_SUCCESS)
		{
			return SCAP_FAILURE;
		}

		nwritten = snprintf(full_cgroup, sizeof(full_cgroup), "%.*s%s", (int)prefix_len, cgi->m_self_v2, cgroup + suffix_skip_len);
	}
	else
	{
		nwritten = snprintf(full_cgroup, sizeof(full_cgroup), "%s", cgroup);
	}

	if(nwritten >= sizeof(full_cgroup))
	{
		return SCAP_FAILURE;
	}

	nwritten = snprintf(cgroup_path, sizeof(cgroup_path), "%s%s", cgi->m_mount_v2, full_cgroup);
	if(nwritten >= sizeof(cgroup_path))
	{
		return SCAP_FAILURE;
	}

	struct scap_cgroup_set found_subsystems = {.len = 0, {'\0'}};
	while(1) // not reached cgroup mountpoint yet
	{
		struct scap_cgroup_set current_subsystems;
		if(get_cgroup_subsystems_v2(cgi, &current_subsystems, cgroup_path) != SCAP_SUCCESS)
		{
			return SCAP_FAILURE;
		}

		FOR_EACH_SUBSYS(&current_subsystems, cgset_subsys)
		{
			if(!scap_cgroup_find_subsys(&found_subsystems, cgset_subsys))
			{
				if(scap_cgroup_printf(cg, "%s=%s", cgset_subsys, full_cgroup) != SCAP_SUCCESS)
				{
					return SCAP_FAILURE;
				}
				if(scap_cgroup_printf(&found_subsystems, "%s", cgset_subsys) != SCAP_SUCCESS)
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

		const char* self_path = NULL;
		size_t len = strlen(subsys_list);
		FOR_EACH_SUBSYS(&cgi->m_self_v1, cgset_subsys)
		{
			if(strncmp(cgset_subsys, subsys_list, len) == 0 && cgset_subsys[len] == '=')
			{
				self_path = cgset_subsys + len + 1;
			}
		}

		while((token = strtok_r(subsys_list, ",", &scratch)) != NULL)
		{
			subsys_list = NULL;
			int ret;

			if(self_path)
			{
				size_t prefix_len;
				size_t suffix_skip_len;
				if(scap_cgroup_prefix_path(self_path, cgroup, &prefix_len, &suffix_skip_len) !=
				   SCAP_SUCCESS)
				{
					ASSERT(false);
					fclose(f);
					return SCAP_SUCCESS;
				}
				ret = scap_cgroup_printf(cg, "%s=%.*s%s", token, (int)prefix_len, self_path,
							 cgroup + suffix_skip_len);
			}
			else
			{
				ret = scap_cgroup_printf(cg, "%s=%s", token, cgroup);
			}

			if(ret == SCAP_FAILURE)
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

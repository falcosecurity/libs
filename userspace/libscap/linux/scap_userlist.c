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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <libscap/scap.h>
#include <libscap/scap-int.h>
#include <libscap/linux/scap_linux_platform.h>
#include <libscap/strl.h>

#include <sys/types.h>

#include <pwd.h>
#include <grp.h>

//
// Allocate and return the list of users on this system
//
int32_t scap_linux_create_userlist(struct scap_platform* platform)
{
	struct scap_linux_platform* handle = (struct scap_linux_platform*)platform;
	bool file_lookup = false;
	FILE *f = NULL;
	char filename[SCAP_MAX_PATH_SIZE];
	uint32_t usercnt, useridx;
	uint32_t grpcnt, grpidx;
	struct passwd *p;
	struct group *g;
	struct scap_userlist *userlist;

	//
	// If the list of users was already allocated for this handle (for example because this is
	// not the first user list block), free it
	//
	if(platform->m_userlist != NULL)
	{
		scap_free_userlist(platform->m_userlist);
		platform->m_userlist = NULL;
	}

	//
	// Memory allocations
	//
	platform->m_userlist = (scap_userlist*)malloc(sizeof(scap_userlist));
	if(platform->m_userlist == NULL)
	{
		snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "userlist allocation failed(1)");
		return SCAP_FAILURE;
	}
	userlist = platform->m_userlist;

	userlist->totsavelen = 0;
	usercnt = 32; // initial user count; will be realloc'd if needed
	userlist->users = (scap_userinfo*)malloc(usercnt * sizeof(scap_userinfo));
	if(userlist->users == NULL)
	{
		snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "userlist allocation failed(2)");
		free(userlist);
		platform->m_userlist = NULL;
		return SCAP_FAILURE;
	}

	grpcnt = 32; // initial group count; will be realloc'd if needed
	userlist->groups = (scap_groupinfo*)malloc(grpcnt * sizeof(scap_groupinfo));
	if(userlist->groups == NULL)
	{
		snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "grouplist allocation failed(2)");
		free(userlist->users);
		free(userlist);
		platform->m_userlist = NULL;
		return SCAP_FAILURE;
	}

	// check for host root
	const char *host_root = scap_get_host_root();
	if(host_root[0] == '\0')
	{
		file_lookup = false;
	}
	else
	{
		file_lookup = true;
	}

	// users
	if(file_lookup)
	{
		snprintf(filename, sizeof(filename), "%s/etc/passwd", host_root);
		f = fopen(filename, "r");
		if(f == NULL)
		{
			// if we don't have it inside the host root, we'll proceed without a list
			free(userlist->users);
			free(userlist->groups);
			free(userlist);
			platform->m_userlist = NULL;
			return SCAP_SUCCESS;
		}
	}
	else
	{
		setpwent();
	}

	for(useridx = 0; file_lookup ? (p = fgetpwent(f)) : (p = getpwent()); useridx++)
	{
		if (useridx == usercnt)
		{
			usercnt<<=1;
			void *tmp = realloc(userlist->users, usercnt * sizeof(scap_userinfo));
			if (tmp)
			{
				userlist->users = tmp;
			}
			else
			{
				snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "userlist allocation failed(2)");
				free(userlist->users);
				free(userlist->groups);
				free(userlist);
				platform->m_userlist = NULL;
				if(file_lookup)
				{
					fclose(f);
				}
				else
				{
					endpwent();
				}
				return SCAP_FAILURE;
			}
		}

		scap_userinfo *user = &userlist->users[useridx];
		user->uid = p->pw_uid;
		user->gid = p->pw_gid;
		
		if(p->pw_name)
		{
			strlcpy(user->name, p->pw_name, sizeof(user->name));
		}
		else
		{
			*user->name = '\0';
		}

		if(p->pw_dir)
		{
			strlcpy(user->homedir, p->pw_dir, sizeof(user->homedir));
		}
		else
		{
			*user->homedir = '\0';
		}

		if(p->pw_shell)
		{
			strlcpy(user->shell, p->pw_shell, sizeof(user->shell));
		}
		else
		{
			*user->shell = '\0';
		}

		userlist->totsavelen += 
			sizeof(uint8_t) + // type
			sizeof(uint32_t) +  // uid
			sizeof(uint32_t) +  // gid
			strlen(user->name) + 2 +
			strlen(user->homedir) + 2 +
			strlen(user->shell) + 2;
	}

	if(file_lookup)
	{
		fclose(f);
	}
	else
	{
		endpwent();
	}

	// if userIdx == 0 -> realloc with size 0 means free, and NULL is returned.
	// so, we will end up with userlist->nusers = 0 and userlist->users NULL.
	userlist->nusers = useridx;
	if (useridx < usercnt)
	{
		// Reduce array size
		scap_userinfo *reduced_userinfos = realloc(userlist->users, useridx * sizeof(scap_userinfo));
		if(reduced_userinfos == NULL && useridx > 0)
		{
			snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "userlist allocation while reducing array size");
			free(userlist->users);
			free(userlist->groups);
			free(userlist);
			platform->m_userlist = NULL;
			return SCAP_FAILURE;
		}
		userlist->users = reduced_userinfos;
	}

	// groups
	if(file_lookup)
	{
		snprintf(filename, sizeof(filename), "%s/etc/group", host_root);
		f = fopen(filename, "r");
		if(f == NULL)
		{
			// if we reached this point we had passwd but we don't have group
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "failed to open %s", filename);
			free(userlist->users);
			free(userlist->groups);
			free(userlist);
			platform->m_userlist = NULL;
			return SCAP_FAILURE;
		}
	}
	else
	{
		setgrent();
	}

	for(grpidx = 0; file_lookup ? (g = fgetgrent(f)) : (g = getgrent()); grpidx++)
	{
		if (grpidx == grpcnt)
		{
			grpcnt<<=1;
			void *tmp = realloc(userlist->groups, grpcnt * sizeof(scap_groupinfo));
			if (tmp)
			{
				userlist->groups = tmp;
			}
			else
			{
				snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "grouplist allocation failed(2)");
				free(userlist->users);
				free(userlist->groups);
				free(userlist);
				platform->m_userlist = NULL;
				if(file_lookup)
				{
					fclose(f);
				}
				else
				{
					endgrent();
				}
				return SCAP_FAILURE;
			}
		}
		scap_groupinfo *group = &userlist->groups[grpidx];
		group->gid = g->gr_gid;

		if(g->gr_name)
		{
			strlcpy(group->name, g->gr_name, sizeof(group->name));
		}
		else
		{
			*group->name = '\0';
		}

		userlist->totsavelen += 
			sizeof(uint8_t) + // type
			sizeof(uint32_t) +  // gid
			strlen(group->name) + 2;
	}

	if(file_lookup)
	{
		fclose(f);
	}
	else
	{
		endgrent();
	}

	// if grpidx == 0 -> realloc with size 0 means free, and NULL is returned.
	// so, we will end up with userlist->ngroups = 0 and userlist->groups NULL.
	userlist->ngroups = grpidx;
	if (grpidx < grpcnt)
	{
		// Reduce array size
		scap_groupinfo *reduced_groups = realloc(userlist->groups, grpidx * sizeof(scap_groupinfo));
		if(reduced_groups == NULL && grpidx > 0)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "grouplist allocation failed(2)");
			free(userlist->users);
			free(userlist->groups);
			free(userlist);
			platform->m_userlist = NULL;
			return SCAP_FAILURE;
		}
		userlist->groups = reduced_groups;
	}
	return SCAP_SUCCESS;
}

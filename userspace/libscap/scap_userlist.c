/*
Copyright (C) 2021 The Falco Authors.

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
#include "scap.h"
#include "scap-int.h"
#include "../common/strlcpy.h"

#if defined(HAS_CAPTURE) && !defined(_WIN32)
#include <sys/types.h>

#include <pwd.h>
#include <grp.h>

//
// Allocate and return the list of users on this system
//
int32_t scap_create_userlist(scap_t* handle)
{
	uint32_t usercnt, useridx;
	uint32_t grpcnt, grpidx;
	struct passwd *p;
	struct group *g;

	//
	// If the list of users was already allocated for this handle (for example because this is
	// not the first user list block), free it
	//
	if(handle->m_userlist != NULL)
	{
		scap_free_userlist(handle->m_userlist);
		handle->m_userlist = NULL;
	}

	//
	// Memory allocations
	//
	handle->m_userlist = (scap_userlist*)malloc(sizeof(scap_userlist));
	if(handle->m_userlist == NULL)
	{
		snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "userlist allocation failed(1)");
		return SCAP_FAILURE;
	}

	handle->m_userlist->totsavelen = 0;
	usercnt = 32; // initial user count; will be realloc'd if needed
	handle->m_userlist->users = (scap_userinfo*)malloc(usercnt * sizeof(scap_userinfo));
	if(handle->m_userlist->users == NULL)
	{
		snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "userlist allocation failed(2)");
		free(handle->m_userlist);
		return SCAP_FAILURE;		
	}

	grpcnt = 32; // initial group count; will be realloc'd if needed
	handle->m_userlist->groups = (scap_groupinfo*)malloc(grpcnt * sizeof(scap_groupinfo));
	if(handle->m_userlist->groups == NULL)
	{
		snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "grouplist allocation failed(2)");
		free(handle->m_userlist->users);
		free(handle->m_userlist);
		return SCAP_FAILURE;		
	}

	// users
	setpwent();
	p = getpwent();

	for(useridx = 0; p; p = getpwent(), useridx++)
	{
		if (useridx == usercnt)
		{
			usercnt<<=1;
			void *tmp = realloc(handle->m_userlist->users, usercnt * sizeof(scap_userinfo));
			if (tmp)
			{
				handle->m_userlist->users = tmp;
			}
			else
			{
				snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "userlist allocation failed(2)");
				free(handle->m_userlist->users);
				free(handle->m_userlist->groups);
				free(handle->m_userlist);
				return SCAP_FAILURE;
			}
		}

		scap_userinfo *user = &handle->m_userlist->users[useridx];
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

		handle->m_userlist->totsavelen += 
			sizeof(uint8_t) + // type
			sizeof(uint32_t) +  // uid
			sizeof(uint32_t) +  // gid
			strlen(user->name) + 2 +
			strlen(user->homedir) + 2 +
			strlen(user->shell) + 2;
	}

	endpwent();
	handle->m_userlist->nusers = useridx;
	if (useridx < usercnt)
	{
		// Reduce array size
		handle->m_userlist->users = realloc(handle->m_userlist->users, useridx * sizeof(scap_userinfo));
	}

	// groups
	setgrent();
	g = getgrent();

	for(grpidx = 0; g; g = getgrent(), grpidx++)
	{
		if (grpidx == grpcnt)
		{
			grpcnt<<=1;
			void *tmp = realloc(handle->m_userlist->groups, grpcnt * sizeof(scap_groupinfo));
			if (tmp)
			{
				handle->m_userlist->groups = tmp;
			}
			else
			{
				snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "grouplist allocation failed(2)");
				free(handle->m_userlist->users);
				free(handle->m_userlist->groups);
				free(handle->m_userlist);
				return SCAP_FAILURE;
			}
		}
		scap_groupinfo *group = &handle->m_userlist->groups[grpidx];
		group->gid = g->gr_gid;

		if(g->gr_name)
		{
			strlcpy(group->name, g->gr_name, sizeof(group->name));
		}
		else
		{
			*group->name = '\0';
		}

		handle->m_userlist->totsavelen += 
			sizeof(uint8_t) + // type
			sizeof(uint32_t) +  // gid
			strlen(group->name) + 2;
	}

	endgrent();
	handle->m_userlist->ngroups = grpidx;
	if (grpidx < grpcnt)
	{
		// Reduce array size
		handle->m_userlist->groups = realloc(handle->m_userlist->groups, grpidx * sizeof(scap_groupinfo));
	}
	return SCAP_SUCCESS;
}

void scap_refresh_userlist(scap_t* handle) {
	scap_free_userlist(handle->m_userlist);
	handle->m_userlist = NULL;
	scap_create_userlist(handle);
}

#else // HAS_CAPTURE
#ifdef WIN32
#include "windows_hal.h"

int32_t scap_create_userlist(scap_t* handle)
{
	return scap_create_userlist_windows(handle);
}
#else // WIN32
int32_t scap_create_userlist(scap_t* handle)
{
	snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "scap_create_userlist not implement on this platform");
	return SCAP_FAILURE;
}
#endif // WIN32
#endif // HAS_CAPTURE

//
// Free a previously allocated list of users
//
void scap_free_userlist(scap_userlist* uhandle)
{
	if(uhandle)
	{
		free(uhandle->users);
		free(uhandle->groups);
		free(uhandle);
	}
}

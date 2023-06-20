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

#include <errno.h>
#include <stdint.h>
#include <stdio.h>

#include "scap_proc_util.h"
#include "scap.h"
#include "scap-int.h"
#include "strerror.h"

static int32_t scap_fd_scan_vtable(struct scap_proclist* proclist, const scap_threadinfo *src_tinfo, scap_threadinfo *dst_tinfo, uint64_t n_fdinfos, const scap_fdinfo* fdinfos, char *error)
{
	uint64_t i;
	scap_fdinfo *fdi = NULL;
	uint32_t res;

	for (i = 0; i < n_fdinfos; i++)
	{
		res = scap_fd_allocate_fdinfo(&fdi, fdinfos[i].fd, fdinfos[i].type);
		if (res != SCAP_SUCCESS)
		{
			snprintf(error, SCAP_LASTERR_SIZE, "can't allocate scap fd handle for file fd %" PRIu64, fdinfos[i].fd);
			return res;
		}

		// copy the contents
		*fdi = fdinfos[i];

		res = scap_add_fd_to_proc_table(proclist, dst_tinfo, fdi, error);
		if (res != SCAP_SUCCESS)
		{
			scap_fd_free_fdinfo(&fdi);
			continue;
		}

		if(proclist->m_proc_callback != NULL)
		{
			if(fdi)
			{
				scap_fd_free_fdinfo(&fdi);
			}
		}
	}

	return SCAP_SUCCESS;
}

int32_t scap_proc_scan_vtable(char *error, struct scap_proclist *proclist, uint64_t n_tinfos, const scap_threadinfo *tinfos, void* ctx, get_fdinfos_fn get_fdinfos)
{
	scap_threadinfo *tinfo;
	uint32_t res = SCAP_SUCCESS;
	uint64_t i;

	for (i = 0; i < n_tinfos; i++)
	{
		bool free_tinfo = false;
		tinfo = calloc(sizeof(*tinfo), 1);
		if(tinfo == NULL)
		{
			return scap_errprintf(error, errno, "can't allocate procinfo struct");
		}

		// copy the structure contents
		*tinfo = tinfos[i];

		//
		// Add the entry to the process table, or fire the notification callback
		//
		if(proclist->m_proc_callback == NULL)
		{
			int32_t uth_status = SCAP_SUCCESS;
			HASH_ADD_INT64(proclist->m_proclist, tid, tinfo);
			if(uth_status != SCAP_SUCCESS)
			{
				snprintf(error, SCAP_LASTERR_SIZE, "process table allocation error (2)");
				free(tinfo);
				return SCAP_FAILURE;
			}
		}
		else
		{
			proclist->m_proc_callback(
				proclist->m_proc_callback_context, tinfo->tid, tinfo, NULL);
			free_tinfo = true;
		}

		if(tinfo->pid == tinfo->tid)
		{
			uint64_t n_fdinfos;
			const scap_fdinfo *fdinfos;

			res = (*get_fdinfos)(ctx, &tinfos[i], &n_fdinfos, &fdinfos);
			if(res == SCAP_SUCCESS)
			{
				res = scap_fd_scan_vtable(proclist, &tinfos[i], tinfo, n_fdinfos, fdinfos, error);
			}
		}

		if(free_tinfo)
		{
			free(tinfo);
		}
	}

	return SCAP_SUCCESS;
}

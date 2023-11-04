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

	for (i = 0; i < n_fdinfos; i++)
	{
		scap_fdinfo fdi = fdinfos[i];
		scap_add_fd_to_proc_table(proclist, dst_tinfo, &fdi, error);
	}

	return SCAP_SUCCESS;
}

int32_t scap_proc_scan_vtable(char *error, struct scap_proclist *proclist, uint64_t n_tinfos, const scap_threadinfo *tinfos, void* ctx, get_fdinfos_fn get_fdinfos)
{
	scap_threadinfo *tinfo;
	scap_threadinfo new_tinfo;
	uint32_t res = SCAP_SUCCESS;
	uint64_t i;

	for (i = 0; i < n_tinfos; i++)
	{
		//
		// Add the entry to the process table, or fire the notification callback
		//
		if(proclist->m_proc_callback == NULL)
		{
			// get a copy of tinfos[i] on the heap
			tinfo = malloc(sizeof(*tinfo));
			if(tinfo == NULL)
			{
				return scap_errprintf(error, errno, "can't allocate procinfo struct");
			}

			// copy the structure contents
			*tinfo = tinfos[i];

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
			// we need a copy because tinfos is const
			// note: we drop the copy, so we lose the filtering information (tinfo->filtered_out)
			// but that is only ever used when reading captures (and that code does not call this function)
			new_tinfo = tinfos[i];

			proclist->m_proc_callback(
				proclist->m_proc_callback_context, new_tinfo.tid, &new_tinfo, NULL);

			tinfo = &new_tinfo;
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
	}

	return SCAP_SUCCESS;
}

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

#include <libscap/scap_proc_util.h>
#include <libscap/scap.h>

int32_t scap_proc_scan_vtable(char *error, struct scap_proclist *proclist, uint64_t n_tinfos, const scap_threadinfo *tinfos, void* ctx, get_fdinfos_fn get_fdinfos)
{
	scap_threadinfo *tinfo;
	scap_threadinfo new_tinfo;
	uint32_t res = SCAP_SUCCESS;
	uint64_t i;

	for (i = 0; i < n_tinfos; i++)
	{
		// we need a copy because tinfos is const
		// note: we drop the copy, so we lose the filtering information (tinfo->filtered_out)
		// but that is only ever used when reading captures (and that code does not call this function)
		new_tinfo = tinfos[i];

		//
		// Add the entry to the process table, or fire the notification callback
		//
		proclist->m_proc_callback(proclist->m_proc_callback_context, error, new_tinfo.tid, &new_tinfo, NULL,
					  &tinfo);

		if(tinfo->pid != tinfo->tid)
		{
			continue;
		}

		uint64_t n_fdinfos;
		const scap_fdinfo *fdinfos;

		res = (*get_fdinfos)(ctx, &tinfos[i], &n_fdinfos, &fdinfos);
		if(res != SCAP_SUCCESS)
		{
			continue;
		}

		uint64_t j;
		for(j = 0; j < n_fdinfos; j++)
		{
			scap_fdinfo fdi = fdinfos[j];
			proclist->m_proc_callback(proclist->m_proc_callback_context, error, tinfo->tid,
						  tinfo, &fdi, NULL);
		}
	}

	return SCAP_SUCCESS;
}

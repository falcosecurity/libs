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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libscap/scap.h>
#include <libscap/scap-int.h>
#include <libscap/strerror.h>

//
// Delete a process entry
//
static void scap_proc_delete(struct scap_proclist* proclist, scap_threadinfo* proc)
{
	//
	// First, free the fd table for this process descriptor
	//
	scap_fd_free_proc_fd_table(proc);

	//
	// Second, remove the process descriptor from the table
	//
	HASH_DEL(proclist->m_proclist, proc);

	//
	// Third, free the memory
	//
	free(proc);
}

//
// Free the process table
//
void scap_proc_free_table(struct scap_proclist* proclist)
{
	struct scap_threadinfo* tinfo;
	struct scap_threadinfo* ttinfo;

	HASH_ITER(hh, proclist->m_proclist, tinfo, ttinfo)
	{
		scap_proc_delete(proclist, tinfo);
	}
}

int32_t scap_fd_add(scap_threadinfo* tinfo, scap_fdinfo* fdinfo)
{
	int32_t uth_status = SCAP_SUCCESS;

	HASH_ADD_INT64(tinfo->fdlist, fd, fdinfo);
	if(uth_status == SCAP_SUCCESS)
	{
		return SCAP_SUCCESS;
	}
	else
	{
		return SCAP_FAILURE;
	}
}

int32_t default_proc_entry_callback(void* context, char* error, int64_t tid, scap_threadinfo* tinfo,
				    scap_fdinfo* fdinfo, scap_threadinfo** new_tinfo)
{
	struct scap_proclist* proclist = (struct scap_proclist*)context;
	if(fdinfo != NULL)
	{
		// add an fd

		// First, find the threadinfo (if not passed by the caller)
		if(tinfo == NULL)
		{
			//
			// Identify the process descriptor
			//
			HASH_FIND_INT64(proclist->m_proclist, &tid, tinfo);

			if(tinfo == NULL)
			{
				//
				// We have the fdinfo but no associated tid, skip it
				//
				return SCAP_SUCCESS;
			}
		}

		int32_t uth_status = SCAP_SUCCESS;
		scap_fdinfo *tfdi;

		// Make sure this fd doesn't already exist
		HASH_FIND_INT64(tinfo->fdlist, &(fdinfo->fd), tfdi);
		if(tfdi != NULL)
		{
			//
			// This can happen if:
			//  - a close() has been dropped when capturing
			//  - an fd has been closed by clone() or execve() (it happens when the fd is opened with the FD_CLOEXEC flag,
			//    which we don't currently parse.
			// In either case, removing the old fd, replacing it with the new one and keeping going is a reasonable
			// choice.
			//
			HASH_DEL(tinfo->fdlist, tfdi);
			free(tfdi);
		}

		scap_fdinfo *new_fdi = malloc(sizeof(*new_fdi));
		if(new_fdi == NULL)
		{
			snprintf(error, SCAP_LASTERR_SIZE, "process table allocation error (1)");
			return SCAP_FAILURE;
		}
		*new_fdi = *fdinfo;

		HASH_ADD_INT64(tinfo->fdlist, fd, new_fdi);
		if(uth_status != SCAP_SUCCESS)
		{
			snprintf(error, SCAP_LASTERR_SIZE, "process table allocation error (2)");
			return SCAP_FAILURE;
		}
	}
	else
	{
		// add a thread
		// get a copy of tinfo on the heap
		scap_threadinfo *heap_tinfo = malloc(sizeof(*heap_tinfo));
		if(heap_tinfo == NULL)
		{
			return scap_errprintf(error, errno, "can't allocate procinfo struct");
		}

		// copy the structure contents
		*heap_tinfo = *tinfo;

		int32_t uth_status = SCAP_SUCCESS;
		HASH_ADD_INT64(proclist->m_proclist, tid, heap_tinfo);
		if(uth_status != SCAP_SUCCESS)
		{
			snprintf(error, SCAP_LASTERR_SIZE, "process table allocation error (2)");
			free(heap_tinfo);
			return SCAP_FAILURE;
		}

		if(new_tinfo)
		{
			*new_tinfo = heap_tinfo;
		}
	}
	return SCAP_SUCCESS;
}

void init_proclist(struct scap_proclist* proclist, proc_entry_callback callback, void* callback_context)
{
	if(callback == NULL)
	{
		proclist->m_proc_callback = default_proc_entry_callback;
		proclist->m_proc_callback_context = proclist;
	}
	else
	{
		proclist->m_proc_callback = callback;
		proclist->m_proc_callback_context = callback_context;
	}

	proclist->m_proclist = NULL;
}
bool scap_alloc_proclist_info(struct ppm_proclist_info **proclist_p, uint32_t n_entries, char* error)
{
	uint32_t memsize;

	if(n_entries >= SCAP_DRIVER_PROCINFO_MAX_SIZE)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "driver process list too big");
		return false;
	}

	memsize = sizeof(struct ppm_proclist_info) +
		  sizeof(struct ppm_proc_info) * n_entries;

	struct ppm_proclist_info *procinfo = (struct ppm_proclist_info*) realloc(*proclist_p, memsize);
	if(procinfo == NULL)
	{
		free(*proclist_p);
		*proclist_p = NULL;
		snprintf(error, SCAP_LASTERR_SIZE, "driver process list allocation error");
		return false;
	}

	if(*proclist_p == NULL)
	{
		procinfo->n_entries = 0;
	}

	procinfo->max_entries = n_entries;
	*proclist_p = procinfo;

	return true;
}

void scap_free_proclist_info(struct ppm_proclist_info *proclist)
{
	free(proclist);
}

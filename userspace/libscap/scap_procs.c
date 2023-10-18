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

#include "scap.h"
#include "scap-int.h"

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

struct scap_threadinfo *scap_proc_alloc(scap_t *handle)
{
	struct scap_threadinfo *tinfo = (struct scap_threadinfo*) calloc(1, sizeof(scap_threadinfo));
	if(tinfo == NULL)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "process table allocation error (1)");
		return NULL;
	}

	return tinfo;
}

void scap_proc_free(scap_t* handle, struct scap_threadinfo* proc)
{
	scap_fd_free_proc_fd_table(proc);
	free(proc);
}

int32_t scap_fd_add(scap_t *handle, scap_threadinfo* tinfo, uint64_t fd, scap_fdinfo* fdinfo)
{
	int32_t uth_status = SCAP_SUCCESS;

	HASH_ADD_INT64(tinfo->fdlist, fd, fdinfo);
	if(uth_status == SCAP_SUCCESS)
	{
		return SCAP_SUCCESS;
	}
	else
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Could not add fd to hash table");
		return SCAP_FAILURE;
	}
}

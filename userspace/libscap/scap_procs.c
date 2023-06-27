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

int32_t scap_check_suppressed(struct scap_suppress* suppress, scap_evt *pevent, uint16_t devid, bool *suppressed, char *error)
{
	uint16_t *lens;
	char *valptr;
	uint32_t j;
	int32_t res = SCAP_SUCCESS;
	const char *comm = NULL;
	uint64_t *ptid = NULL;
	scap_tid *stid;

	*suppressed = false;

	/* If we have neither suppressed comms nor suppressed tids we return immediately */
	if(suppress->m_num_suppressed_comms == 0 && suppress->m_suppressed_tids == NULL)
	{
		return SCAP_SUCCESS;
	}

	// For events that can create a new tid (fork, vfork, clone),
	// we need to check the comm, which might also update the set
	// of suppressed tids.

	switch(pevent->type)
	{
	case PPME_SYSCALL_CLONE_20_X:
	case PPME_SYSCALL_FORK_20_X:
	case PPME_SYSCALL_VFORK_20_X:
	case PPME_SYSCALL_EXECVE_19_X:
	case PPME_SYSCALL_EXECVEAT_X:
	case PPME_SYSCALL_CLONE3_X:

		lens = (uint16_t *)((char *)pevent + sizeof(struct ppm_evt_hdr));
		valptr = (char *)lens + pevent->nparams * sizeof(uint16_t);

		if(pevent->nparams < 14)
		{
			snprintf(error, SCAP_LASTERR_SIZE, "Could not find process comm in event argument list");
			return SCAP_FAILURE;
		}

		// For all of these events, the comm is argument 14,
		// so we need to walk the list of params that far to
		// find the comm.
		for(j = 0; j < 13; j++)
		{
			if(j == 5)
			{
				ptid = (uint64_t *) valptr;
			}

			valptr += lens[j];
		}

		if(ptid == NULL)
		{
			snprintf(error, SCAP_LASTERR_SIZE, "Could not find ptid in event argument list");
			return SCAP_FAILURE;
		}

		comm = valptr;

		if((res = scap_update_suppressed(suppress,
						 comm,
						 pevent->tid, *ptid,
						 suppressed)) != SCAP_SUCCESS)
		{
			// scap_update_suppressed already set handle->m_lasterr on error.
			return res;
		}

		break;

	default:

		if(suppress->m_suppressed_tids)
		{
			uint16_t slot = (devid & (SCAP_CACHE_DEVID_MAX - 1));
			if(suppress->m_devid_tid_stid_cache[slot].tid == pevent->tid)
			{
				stid = suppress->m_devid_tid_stid_cache[slot].stid; // use cached
			}
			else
			{
				HASH_FIND_INT64(suppress->m_suppressed_tids, &(pevent->tid), stid);
				suppress->m_devid_tid_stid_cache[slot].tid = pevent->tid; //  re-cache
				suppress->m_devid_tid_stid_cache[slot].stid = stid; // re-cache
			}
		}
		else
		{
			// suppressed TIDs hash table is not allocated / used
			stid = NULL;
		}

		// When threads exit they are always removed and no longer suppressed.
		if(pevent->type == PPME_PROCEXIT_1_E)
		{
			if(stid != NULL)
			{
				scap_remove_and_free_suppressed(suppress, stid);
				*suppressed = true;
			}
			else
			{
				*suppressed = false;
			}
		}
		else
		{
			*suppressed = (stid != NULL);
		}

		break;
	}

	return SCAP_SUCCESS;
}

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

int32_t scap_getpid_global(scap_t* handle, int64_t* pid)
{
	if(handle->m_vtable)
	{
		return handle->m_vtable->getpid_global(handle->m_engine, pid, handle->m_lasterr);
	}

	ASSERT(false);
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Cannot get pid (capture not enabled)");
	return SCAP_FAILURE;
}

//
// Delete a process entry
//
void scap_proc_delete(scap_t* handle, scap_threadinfo* proc)
{
	//
	// First, free the fd table for this process descriptor
	//
	scap_fd_free_proc_fd_table(proc);

	//
	// Second, remove the process descriptor from the table
	//
	HASH_DEL(handle->m_proclist.m_proclist, proc);

	//
	// Third, free the memory
	//
	free(proc);
}

//
// Free the process table
//
void scap_proc_free_table(scap_t* handle)
{
	struct scap_threadinfo* tinfo;
	struct scap_threadinfo* ttinfo;

	HASH_ITER(hh, handle->m_proclist.m_proclist, tinfo, ttinfo)
	{
		scap_proc_delete(handle, tinfo);
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

int32_t scap_proc_add(scap_t* handle, uint64_t tid, scap_threadinfo* tinfo)
{
	int32_t uth_status = SCAP_SUCCESS;

	HASH_ADD_INT64(handle->m_proclist.m_proclist, tid, tinfo);
	if(uth_status == SCAP_SUCCESS)
	{
		return SCAP_SUCCESS;
	}
	else
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Could not add tid to hash table");
		return SCAP_FAILURE;
	}
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

int32_t scap_update_suppressed(scap_t *handle,
			       const char *comm,
			       uint64_t tid, uint64_t ptid,
			       bool *suppressed)
{
	uint32_t i;
	scap_tid *stid;

	*suppressed = false;

	HASH_FIND_INT64(handle->m_suppressed_tids, &ptid, stid);

	if(stid != NULL)
	{
		*suppressed = true;
	}
	else
	{
		for(i=0; i < handle->m_num_suppressed_comms; i++)
		{
			if(strcmp(handle->m_suppressed_comms[i], comm) == 0)
			{
				*suppressed = true;
				break;
			}
		}
	}

	// Also check to see if the tid is already in the set of
	// suppressed tids.

	HASH_FIND_INT64(handle->m_suppressed_tids, &tid, stid);

	if(*suppressed && stid == NULL)
	{
		stid = (scap_tid *) malloc(sizeof(scap_tid));
		stid->tid = tid;
		int32_t uth_status = SCAP_SUCCESS;

		HASH_ADD_INT64(handle->m_suppressed_tids, tid, stid);

		if(uth_status != SCAP_SUCCESS)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "can't add tid to suppressed hash table");
			free(stid);
			return SCAP_FAILURE;
		}
		*suppressed = true;
	}
	else if (!*suppressed && stid != NULL)
	{
		HASH_DEL(handle->m_suppressed_tids, stid);
		free(stid);
		*suppressed = false;
	}

	return SCAP_SUCCESS;
}

int32_t scap_check_suppressed(scap_t *handle, scap_evt *pevent, bool *suppressed)
{
	uint16_t *lens;
	char *valptr;
	uint32_t j;
	int32_t res = SCAP_SUCCESS;
	const char *comm = NULL;
	uint64_t *ptid = NULL;
	scap_tid *stid;

	*suppressed = false;

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
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Could not find process comm in event argument list");
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
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Could not find ptid in event argument list");
			return SCAP_FAILURE;
		}

		comm = valptr;

		if((res = scap_update_suppressed(handle,
						 comm,
						 pevent->tid, *ptid,
						 suppressed)) != SCAP_SUCCESS)
		{
			// scap_update_suppressed already set handle->m_lasterr on error.
			return res;
		}

		break;

	default:

		HASH_FIND_INT64(handle->m_suppressed_tids, &(pevent->tid), stid);

		// When threads exit they are always removed and no longer suppressed.
		if(pevent->type == PPME_PROCEXIT_1_E)
		{
			if(stid != NULL)
			{
				HASH_DEL(handle->m_suppressed_tids, stid);
				free(stid);
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

int32_t scap_fd_scan_vtable(scap_t *handle, const scap_threadinfo *src_tinfo, scap_threadinfo *dst_tinfo, char *error)
{
	uint64_t n_fdinfos, i;
	const scap_fdinfo *fdinfos;
	scap_fdinfo *fdi = NULL;
	uint32_t res;

	res = handle->m_vtable->get_fdinfos(handle->m_engine, src_tinfo, &n_fdinfos, &fdinfos);
	if (res != SCAP_SUCCESS)
	{
		return res;
	}

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

		res = scap_add_fd_to_proc_table(&handle->m_proclist, dst_tinfo, fdi, error);
		if (res != SCAP_SUCCESS)
		{
			scap_fd_free_fdinfo(&fdi);
			continue;
		}

		if(handle->m_proclist.m_proc_callback != NULL)
		{
			if(fdi)
			{
				scap_fd_free_fdinfo(&fdi);
			}
		}
	}

	return SCAP_SUCCESS;
}

int32_t scap_proc_scan_vtable(char *error, scap_t *handle)
{
	const scap_threadinfo *tinfos;
	scap_threadinfo *tinfo;
	uint32_t res = SCAP_SUCCESS;
	uint64_t n_tinfos, i;

	res = handle->m_vtable->get_threadinfos(handle->m_engine, &n_tinfos, &tinfos);
	if (res != SCAP_SUCCESS)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "cannot get system thread information: %s", handle->m_lasterr);
		return res;
	}

	for (i = 0; i < n_tinfos; i++)
	{
		bool free_tinfo = false;
		if((tinfo = scap_proc_alloc(handle)) == NULL)
		{
			// Error message saved in handle->m_lasterr
			snprintf(error, SCAP_LASTERR_SIZE, "can't allocate procinfo struct: %s", handle->m_lasterr);
			return SCAP_FAILURE;
		}

		// copy the structure contents
		*tinfo = tinfos[i];

		//
		// Add the entry to the process table, or fire the notification callback
		//
		if(handle->m_proclist.m_proc_callback == NULL)
		{
			int32_t uth_status = SCAP_SUCCESS;
			HASH_ADD_INT64(handle->m_proclist.m_proclist, tid, tinfo);
			if(uth_status != SCAP_SUCCESS)
			{
				snprintf(error, SCAP_LASTERR_SIZE, "process table allocation error (2)");
				free(tinfo);
				return SCAP_FAILURE;
			}
		}
		else
		{
			handle->m_proclist.m_proc_callback(
				handle->m_proclist.m_proc_callback_context,
				handle->m_proclist.m_main_handle, tinfo->tid, tinfo, NULL);
			free_tinfo = true;
		}

		if(tinfo->pid == tinfo->tid)
		{
			res = scap_fd_scan_vtable(handle, &tinfos[i], tinfo, error);
		}

		if(free_tinfo)
		{
			free(tinfo);
		}
	}

	return SCAP_SUCCESS;
}

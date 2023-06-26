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

#include <stdlib.h>
#include <string.h>

#include "scap_suppress.h"

#include "scap_const.h"
#include "scap_limits.h"

int32_t scap_suppress_events_comm_impl(struct scap_suppress *suppress, const char *comm)
{
	// If the comm is already present in the list, do nothing
	uint32_t i;
	for(i=0; i<suppress->m_num_suppressed_comms; i++)
	{
		if(strcmp(suppress->m_suppressed_comms[i], comm) == 0)
		{
			return SCAP_SUCCESS;
		}
	}

	if(suppress->m_num_suppressed_comms >= SCAP_MAX_SUPPRESSED_COMMS)
	{
		return SCAP_FAILURE;
	}

	suppress->m_num_suppressed_comms++;
	char **expanded_suppressed_comms = (char **) realloc(suppress->m_suppressed_comms,
						       suppress->m_num_suppressed_comms * sizeof(char *));
	if(expanded_suppressed_comms == NULL)
	{
		for(i=0; i<suppress->m_num_suppressed_comms - 1; i++) {
			free(suppress->m_suppressed_comms[i]);
		}
		free(suppress->m_suppressed_comms);
		return SCAP_FAILURE;
	}
	suppress->m_suppressed_comms = expanded_suppressed_comms;

	suppress->m_suppressed_comms[suppress->m_num_suppressed_comms-1] = strdup(comm);

	return SCAP_SUCCESS;
}

int32_t scap_suppress_events_tid_impl(struct scap_suppress *suppress, int64_t tid)
{
	scap_tid *stid = (scap_tid *)malloc(sizeof(scap_tid));
	if(stid == NULL)
	{
		return SCAP_FAILURE;
	}

	stid->tid = tid;

	int32_t uth_status = SCAP_SUCCESS;
	HASH_ADD_INT64(suppress->m_suppressed_tids, tid, stid);
	if(uth_status != SCAP_SUCCESS)
	{
		free(stid);
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

int32_t scap_suppress_init(struct scap_suppress* suppress, const char** suppressed_comms)
{
	suppress->m_suppressed_comms = NULL;
	suppress->m_num_suppressed_comms = 0;
	suppress->m_suppressed_tids = NULL;
	suppress->m_num_suppressed_evts = 0;

	if(suppressed_comms)
	{
		uint32_t i;
		const char *comm;
		for(i = 0, comm = suppressed_comms[i]; comm && i < SCAP_MAX_SUPPRESSED_COMMS; i++, comm = suppressed_comms[i])
		{
			int32_t res;
			if((res = scap_suppress_events_comm_impl(suppress, comm)) != SCAP_SUCCESS)
			{
				return res;
			}
		}
	}

	return SCAP_SUCCESS;
}

bool scap_check_suppressed_tid_impl(struct scap_suppress* suppress, int64_t tid)
{
	scap_tid *stid;
	HASH_FIND_INT64(suppress->m_suppressed_tids, &tid, stid);

	return (stid != NULL);
}

void scap_suppress_close(struct scap_suppress* suppress)
{
	if(suppress->m_suppressed_comms)
	{
		uint32_t i;
		for(i=0; i < suppress->m_num_suppressed_comms; i++)
		{
			free(suppress->m_suppressed_comms[i]);
		}
		free(suppress->m_suppressed_comms);
		suppress->m_suppressed_comms = NULL;
	}

	if(suppress->m_suppressed_tids)
	{
		struct scap_tid *tid;
		struct scap_tid *ttid;
		HASH_ITER(hh, suppress->m_suppressed_tids, tid, ttid)
		{
			scap_remove_and_free_suppressed(suppress, tid);
		}

		suppress->m_suppressed_tids = NULL;
	}
}

int32_t scap_update_suppressed(struct scap_suppress *suppress,
			       const char *comm,
			       uint64_t tid, uint64_t ptid,
			       bool *suppressed)
{
	uint32_t i;
	scap_tid *stid;

	*suppressed = false;

	HASH_FIND_INT64(suppress->m_suppressed_tids, &ptid, stid);

	/* We suppress the actual tid in 2 cases:
	 * 1. Its parent is suppressed.
	 * 2. Its comm is in the suppressed list
	 */
	if(stid != NULL)
	{
		*suppressed = true;
		/* Please note that we don't update the suppressed_comms list
		 * even if the comm of the child could be different from the parent one.
		 * The only case in which we update the suppressed_comms list is when
		 * we explicitly call the `scap_suppress_events_comm` API.
		 */
	}
	else
	{
		for(i=0; i < suppress->m_num_suppressed_comms; i++)
		{
			if(strcmp(suppress->m_suppressed_comms[i], comm) == 0)
			{
				*suppressed = true;
				break;
			}
		}
	}

	// Also check to see if the tid is already in the set of
	// suppressed tids.

	HASH_FIND_INT64(suppress->m_suppressed_tids, &tid, stid);

	if(*suppressed && stid == NULL)
	{
		/* if the tid should be suppressed but we don't have it in the hash table we add it */
		if(scap_suppress_events_tid_impl(suppress, tid) == SCAP_SUCCESS)
		{
			*suppressed = true;
		}
		else
		{
			return SCAP_FAILURE;
		}
	}
	else if (!*suppressed && stid != NULL)
	{
		/* if the tid shouldn't be suppressed but we have it in the hash table we remove it */
		scap_remove_and_free_suppressed(suppress, stid);
		*suppressed = false;
	}

	return SCAP_SUCCESS;
}

void scap_remove_and_free_suppressed(struct scap_suppress *suppress, scap_tid *stid)
{
	uint16_t slot;

	// Remove from cache around hash table.
	for(slot = 0; slot < SCAP_CACHE_DEVID_MAX; slot ++)
	{
		if(stid == suppress->m_devid_tid_stid_cache[slot].stid)
		{
			suppress->m_devid_tid_stid_cache[slot].tid = 0;
			suppress->m_devid_tid_stid_cache[slot].stid = NULL;
		}
	}
	// Remove from hash table and free().
	HASH_DEL(suppress->m_suppressed_tids, stid);
	free(stid);
}

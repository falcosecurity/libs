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

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "uthash.h"

typedef struct scap_tid
{
	uint64_t tid;

	UT_hash_handle hh; ///< makes this structure hashable
} scap_tid;


struct scap_suppress
{
	// The set of process names that are suppressed
	char **m_suppressed_comms;
	uint32_t m_num_suppressed_comms;

	// The active set of threads that are suppressed
	scap_tid *m_suppressed_tids;

	// The number of events that were skipped due to the comm
	// matching an entry in m_suppressed_comms.
	uint64_t m_num_suppressed_evts;
};

int32_t scap_suppress_init(struct scap_suppress* suppress, const char** suppressed_comms);
int32_t scap_suppress_events_comm_impl(struct scap_suppress *suppress, const char *comm);
bool scap_check_suppressed_tid_impl(struct scap_suppress* suppress, int64_t tid);

// Possibly add or remove the provided comm, tid combination to the
// set of suppressed processes. If the ptid is currently in the
// suppressed set, the tid will always be added to the suppressed
// set. Otherwise, the tid will be added if the comm matches an entry
// in suppressed_comms.
//
// Sets *suppressed to whether, after this check, the tid is suppressed.
//
// Returns SCAP_FAILURE if we tried to add the tid to the suppressed
// tid set, but it could *not* be added, SCAP_SUCCESS otherwise.
int32_t scap_update_suppressed(struct scap_suppress *suppress,
			       const char *comm,
			       uint64_t tid, uint64_t ptid,
			       bool *suppressed);

void scap_suppress_close(struct scap_suppress* suppress);

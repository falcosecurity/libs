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

#include <stdio.h>
#include <stdlib.h>

struct noop_engine
{
	char *m_lasterr;
};

#define SCAP_HANDLE_T struct noop_engine

#include "noop.h"
#include "scap.h"
#include "strlcpy.h"

struct noop_engine* noop_alloc_handle(scap_t* main_handle, char* lasterr_ptr)
{
	struct noop_engine *engine = calloc(1, sizeof(struct noop_engine));
	if(engine)
	{
		engine->m_lasterr = lasterr_ptr;
	}
	return engine;
}

void noop_free_handle(struct scap_engine_handle engine)
{
	free(engine.m_handle);
}

int noop_close_engine(struct scap_engine_handle engine)
{
	return SCAP_SUCCESS;
}

int32_t noop_next(struct scap_engine_handle handle, scap_evt** pevent, uint16_t* pcpuid)
{
	return SCAP_EOF;
}

int32_t noop_start_capture(struct scap_engine_handle engine)
{
	return SCAP_SUCCESS;
}

int32_t noop_stop_capture(struct scap_engine_handle engine)
{
	return SCAP_SUCCESS;
}

int32_t unimplemented_op(char* err, size_t err_size)
{
	strlcpy(err, "Operation not implemented", err_size);
	return SCAP_FAILURE;
}

int32_t noop_configure(struct scap_engine_handle engine, enum scap_setting setting, unsigned long arg1, unsigned long arg2)
{
	// the open path disables dropping mode so report success even if we
	// don't really support it
	if(setting == SCAP_SAMPLING_RATIO && arg2 == 0)
	{
		return SCAP_SUCCESS;
	}
	return unimplemented_op(engine.m_handle->m_lasterr, SCAP_LASTERR_SIZE);
}

int32_t noop_get_stats(struct scap_engine_handle engine, scap_stats* stats)
{
	return SCAP_SUCCESS;
}

int32_t noop_get_n_tracepoint_hit(struct scap_engine_handle engine, long* ret)
{
	return SCAP_NOT_SUPPORTED;
}

uint32_t noop_get_n_devs(struct scap_engine_handle engine)
{
	return SCAP_SUCCESS;
}

uint64_t noop_get_max_buf_used(struct scap_engine_handle engine)
{
	return SCAP_SUCCESS;
}

int32_t noop_get_threadlist(struct scap_engine_handle engine, struct ppm_proclist_info **procinfo_p, char *lasterr)
{
	return SCAP_NOT_SUPPORTED;
}

int32_t noop_get_vxid(struct scap_engine_handle engine, uint64_t xid, int64_t* vxid)
{
	return SCAP_NOT_SUPPORTED;
}

int32_t noop_getpid_global(struct scap_engine_handle engine, int64_t* pid, char* error)
{
	return SCAP_NOT_SUPPORTED;
}

const struct scap_vtable scap_noop_engine = {
	.name = "noop",
	.mode = SCAP_MODE_NODRIVER,
	.savefile_ops = NULL,

	.alloc_handle = noop_alloc_handle,
	.init = NULL,
	.free_handle = noop_free_handle,
	.close = noop_close_engine,
	.next = noop_next,
	.start_capture = noop_start_capture,
	.stop_capture = noop_stop_capture,
	.configure = noop_configure,
	.get_stats = noop_get_stats,
	.get_n_tracepoint_hit = noop_get_n_tracepoint_hit,
	.get_n_devs = noop_get_n_devs,
	.get_max_buf_used = noop_get_max_buf_used,
	.get_threadlist = noop_get_threadlist,
	.get_vpid = noop_get_vxid,
	.get_vtid = noop_get_vxid,
	.getpid_global = noop_getpid_global,
};

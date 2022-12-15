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

struct scap;
struct scap_test_input_data;

struct test_input_engine
{
	char* m_lasterr;
	struct scap_test_input_data *m_data;
};

typedef struct test_input_engine test_input_engine;

#define SCAP_HANDLE_T struct test_input_engine

#include "noop.h"

#include "scap.h"
#include "scap-int.h"
#include "strlcpy.h"

static struct test_input_engine* alloc_handle(scap_t* main_handle, char* lasterr_ptr)
{
	struct test_input_engine *engine = calloc(1, sizeof(struct test_input_engine));
	if(engine == NULL)
	{
		return NULL;
	}

	engine->m_lasterr = lasterr_ptr;

	return engine;
}

static int32_t next(struct scap_engine_handle handle, scap_evt** pevent, uint16_t* pcpuid)
{
	test_input_engine *engine = handle.m_handle;
	scap_test_input_data *data = engine->m_data;

	if (!data->events || data->event_count == 0)
	{
		return SCAP_EOF;
	}

	*pevent = *(data->events++);
	data->event_count--;

	return SCAP_SUCCESS;
}


static int32_t get_threadinfos(struct scap_engine_handle handle, uint64_t *n, const scap_threadinfo **tinfos)
{
	test_input_engine *engine = handle.m_handle;
	scap_test_input_data *data = engine->m_data;

	*tinfos = data->threads;
	*n = data->thread_count;

	return SCAP_SUCCESS;
}

static int32_t get_fdinfos(struct scap_engine_handle handle, const scap_threadinfo *tinfo, uint64_t *n, const scap_fdinfo **fdinfos)
{
	test_input_engine *engine = handle.m_handle;
	scap_test_input_data *data = engine->m_data;
	size_t i;

	for (i = 0; i < data->thread_count; i++)
	{
		if(data->threads[i].tid == tinfo->tid) {
			*fdinfos = data->fdinfo_data[i].fdinfos;
			*n = data->fdinfo_data[i].fdinfo_count;
			return SCAP_SUCCESS;
		}
	}

	snprintf(engine->m_lasterr, SCAP_LASTERR_SIZE, "Could not find thread info for tid %lu", tinfo->tid);
	return SCAP_FAILURE;
}

static int32_t init(scap_t* main_handle, scap_open_args* oargs)
{
	test_input_engine *engine = main_handle->m_engine.m_handle;
	struct scap_test_input_engine_params *params = oargs->engine_params;
	engine->m_data = params->test_input_data;

	if (engine->m_data == NULL) {
		strlcpy(engine->m_lasterr, "No test input data provided", SCAP_LASTERR_SIZE);
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

const struct scap_vtable scap_test_input_engine = {
	.name = TEST_INPUT_ENGINE,
	.mode = SCAP_MODE_LIVE,
	.savefile_ops = NULL,

	.alloc_handle = alloc_handle,
	.init = init,
	.free_handle = noop_free_handle,
	.close = noop_close_engine,
	.next = next,
	.start_capture = noop_start_capture,
	.stop_capture = noop_stop_capture,
	.configure = noop_configure,
	.get_stats = noop_get_stats,
	.get_n_tracepoint_hit = noop_get_n_tracepoint_hit,
	.get_n_devs = noop_get_n_devs,
	.get_max_buf_used = noop_get_max_buf_used,
	.get_threadlist = noop_get_threadlist,
	.get_threadinfos = get_threadinfos,
	.get_fdinfos = get_fdinfos,
	.get_vpid = noop_get_vxid,
	.get_vtid = noop_get_vxid,
	.getpid_global = noop_getpid_global,
};

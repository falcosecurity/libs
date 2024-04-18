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

#include <libscap/engine/noop/noop.h>

#include <libscap/scap.h>
#include <libscap/scap-int.h>
#include <libscap/scap_proc_util.h>
#include <libscap/strl.h>

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

static int32_t next(struct scap_engine_handle handle, scap_evt** pevent, uint16_t* pdevid, uint32_t* pflags)
{
	test_input_engine *engine = handle.m_handle;
	scap_test_input_data *data = engine->m_data;

	if (!data->events || data->event_count == 0)
	{
		return SCAP_TIMEOUT;
	}

	*pevent = *(data->events++);
	data->event_count--;
	/* All the events are sent by device 1 */
	*pdevid = 1;
	*pflags = 0;
	return SCAP_SUCCESS;
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
	.get_stats_v2 = noop_get_stats_v2,
	.get_n_tracepoint_hit = noop_get_n_tracepoint_hit,
	.get_n_devs = noop_get_n_devs,
	.get_max_buf_used = noop_get_max_buf_used,
	.get_api_version = NULL,
	.get_schema_version = NULL,
};

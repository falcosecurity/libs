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
#include <libscap/engine/test_input/test_input_platform.h>
#include <libscap/scap.h> // for scap_threadinfo
#include <libscap/scap_const.h>
#include <libscap/scap_open.h>
#include <libscap/scap_proc_util.h>
#include <libscap/engine/test_input/test_input_public.h>
#include <libscap/strl.h>

static int32_t get_fdinfos(void* ctx, const scap_threadinfo *tinfo, uint64_t *n, const scap_fdinfo **fdinfos)
{
	struct scap_test_input_platform * platform = ctx;
	scap_test_input_data *data = platform->m_data;
	size_t i;

	for (i = 0; i < data->thread_count; i++)
	{
		if(data->threads[i].tid == tinfo->tid) {
			*fdinfos = data->fdinfo_data[i].fdinfos;
			*n = data->fdinfo_data[i].fdinfo_count;
			return SCAP_SUCCESS;
		}
	}

	snprintf(platform->m_lasterr, SCAP_LASTERR_SIZE, "Could not find thread info for tid %lu", tinfo->tid);
	return SCAP_FAILURE;
}

int32_t scap_test_input_init_platform(struct scap_platform* platform, char* lasterr, struct scap_engine_handle engine, struct scap_open_args* oargs)
{
	struct scap_test_input_engine_params *params = oargs->engine_params;
	struct scap_test_input_platform* test_input_platform = (struct scap_test_input_platform*)platform;

	test_input_platform->m_data = params->test_input_data;
	test_input_platform->m_lasterr = lasterr;

	if (test_input_platform->m_data == NULL)
	{
		strlcpy(lasterr, "No test input data provided", SCAP_LASTERR_SIZE);
		return SCAP_FAILURE;
	}

	return scap_proc_scan_vtable(
		lasterr,
		&platform->m_proclist,
		params->test_input_data->thread_count,
		params->test_input_data->threads,
		test_input_platform,
		get_fdinfos);
}

static void scap_test_input_free_platform(struct scap_platform* platform)
{
	free(platform);
}

static bool scap_test_input_is_thread_alive(struct scap_platform* platform, int64_t pid, int64_t tid, const char* comm)
{
	return false;
}

static const struct scap_platform_vtable scap_test_input_platform = {
	.init_platform = scap_test_input_init_platform,
	.free_platform = scap_test_input_free_platform,
	.is_thread_alive = scap_test_input_is_thread_alive,
};

struct scap_platform* scap_test_input_alloc_platform(proc_entry_callback proc_callback, void* proc_callback_context)
{
	struct scap_test_input_platform* platform = calloc(sizeof(*platform), 1);

	if(platform == NULL)
	{
		return NULL;
	}

	struct scap_platform* generic = &platform->m_generic;
	generic->m_vtable = &scap_test_input_platform;

	init_proclist(&platform->m_generic.m_proclist, proc_callback, proc_callback_context);

	return generic;
}

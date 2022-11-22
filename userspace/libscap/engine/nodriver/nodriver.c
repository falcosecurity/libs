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

#define SCAP_HANDLE_T struct nodriver_engine

#include "nodriver.h"
#include "noop.h"

#include "scap.h"
#include "strlcpy.h"
#include "gettimeofday.h"
#include "sleep.h"

static struct nodriver_engine* alloc_handle(scap_t* main_handle, char* lasterr_ptr)
{
	struct nodriver_engine *engine = calloc(1, sizeof(struct nodriver_engine));
	if(engine)
	{
		engine->m_lasterr = lasterr_ptr;
	}
	return engine;
}

static int32_t next(struct scap_engine_handle handle, scap_evt** pevent, uint16_t* pcpuid)
{
	static scap_evt evt;
	evt.len = 0;
	evt.tid = -1;
	evt.type = PPME_SCAPEVENT_X;
	evt.nparams = 0;

	sleep_ms(100);

	evt.ts = get_timestamp_ns();
	*pevent = &evt;
	return SCAP_SUCCESS;
}

const struct scap_vtable scap_nodriver_engine = {
	.name = NODRIVER_ENGINE,
	.mode = SCAP_MODE_NODRIVER,
	.savefile_ops = NULL,

	.alloc_handle = alloc_handle,
	.init = NULL,
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
	.get_vpid = noop_get_vxid,
	.get_vtid = noop_get_vxid,
	.getpid_global = noop_getpid_global,
};

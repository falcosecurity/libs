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

#define HANDLE(engine) ((struct nodriver_engine*)(engine.m_handle))

#include <libscap/engine/nodriver/nodriver.h>
#include <libscap/engine/noop/noop.h>

#include <libscap/scap.h>
#include <libscap/strl.h>
#include <libscap/scap_gettimeofday.h>
#include <libscap/scap_sleep.h>

static void* alloc_handle(scap_t* main_handle, char* lasterr_ptr) {
	struct nodriver_engine* engine = calloc(1, sizeof(struct nodriver_engine));
	if(engine) {
		engine->m_lasterr = lasterr_ptr;
	}
	return engine;
}

static int32_t init(scap_t* handle, scap_open_args* oargs) {
	return SCAP_SUCCESS;
}

static int32_t next(struct scap_engine_handle handle,
                    scap_evt** pevent,
                    uint16_t* pdevid,
                    uint32_t* pflags) {
	// Define a packed structure allowing to encode a PPME_SCAPEVENT_E event on the fly.
#if defined _MSC_VER
#pragma pack(push)
#pragma pack(1)
#else
#pragma pack(push, 1)
#endif
	struct scapevent_e_t {
		scap_evt header;
		uint16_t lengths[2];
		uint8_t data[12];
	};
#pragma pack(pop)

	// Statically allocate a PPME_SCAPEVENT_E event.
	static struct scapevent_e_t evt = {
	        .header = {0,                          // ts
	                   (uint64_t)-1,               // tid
	                   sizeof(scap_evt) + 4 + 12,  // header + lengths + data
	                   PPME_SCAPEVENT_E,           // type
	                   2},                         // nparams
	        .lengths = {4, 8},                     // lengths array
	        .data = {0},                           // Set all parameter values to 0.
	};

	sleep_ms(100);

	const uint64_t ts = get_timestamp_ns();
	memcpy(&evt.header.ts, &ts, sizeof(ts));
	*pevent = &evt.header;
	*pdevid = 0;
	*pflags = 0;
	return SCAP_SUCCESS;
}

const struct scap_vtable scap_nodriver_engine = {
        .name = NODRIVER_ENGINE,
        .savefile_ops = NULL,

        .alloc_handle = alloc_handle,
        .init = init,
        .free_handle = noop_free_handle,
        .close = noop_close_engine,
        .next = next,
        .next_from_buffer = noop_next_from_buffer,
        .get_n_allocated_buffer_handles = noop_get_n_allocated_buffer_handles,
        .reserve_buffer_handle = noop_reserve_buffer_handle,
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

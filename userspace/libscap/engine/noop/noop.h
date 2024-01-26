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

#pragma once

#include <libscap/engine_handle.h>
#include <libscap/scap_vtable.h>

typedef struct scap scap_t;
typedef struct ppm_evt_hdr scap_evt;
typedef struct scap_stats scap_stats;
typedef struct metrics_v2 metrics_v2;

struct noop_engine* noop_alloc_handle(scap_t* main_handle, char* lasterr_ptr);
void noop_free_handle(struct scap_engine_handle engine);
int noop_close_engine(struct scap_engine_handle engine);
int32_t noop_next(struct scap_engine_handle handle, scap_evt** pevent, uint16_t* pdevid, uint32_t* pflags);
int32_t noop_start_capture(struct scap_engine_handle engine);
int32_t noop_stop_capture(struct scap_engine_handle engine);
int32_t unimplemented_op(char* err, size_t err_size);
int32_t noop_configure(struct scap_engine_handle engine, enum scap_setting setting, unsigned long arg1, unsigned long arg2);
int32_t noop_get_stats(struct scap_engine_handle engine, scap_stats* stats);
const struct metrics_v2* noop_get_stats_v2(struct scap_engine_handle engine, uint32_t flags, uint32_t* nstats, int32_t* rc);
int32_t noop_get_n_tracepoint_hit(struct scap_engine_handle engine, long* ret);
uint32_t noop_get_n_devs(struct scap_engine_handle engine);
uint64_t noop_get_max_buf_used(struct scap_engine_handle engine);

extern const struct scap_vtable scap_noop_engine;

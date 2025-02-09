// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

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

#ifdef __cplusplus
extern "C" {
#endif

#include <libscap/engine/savefile/converter/results.h>

typedef struct ppm_evt_hdr scap_evt;

// 50 consecutive conversions on the same event should be more than enough
#define MAX_CONVERSION_BOUNDARY 50

struct scap_convert_buffer;

struct scap_convert_buffer* scap_convert_alloc_buffer();
conversion_result scap_convert_event(struct scap_convert_buffer* buf,
                                     scap_evt* new_evt,
                                     scap_evt* evt_to_convert,
                                     char* error);
void scap_convert_free_buffer(struct scap_convert_buffer* buf);

bool is_conversion_needed(scap_evt* evt_to_convert);

// Only for testing purposes
scap_evt* scap_retrieve_evt_from_converter_storage(struct scap_convert_buffer* buf, uint64_t tid);

#ifdef __cplusplus
};
#endif

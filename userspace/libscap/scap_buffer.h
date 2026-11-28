// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2026 The Falco Authors.

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

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Opaque handle identifying one of the buffers an engine reads events from.
 *
 * Handles are obtained with `scap_buffer_reserve_handle()` and consumed with
 * `scap_buffer_next()`. Their value is meaningful only to the engine that produced them.
 */
typedef uint32_t scap_buffer_t;

/**
 * @brief Value returned when a buffer handle cannot be reserved.
 */
#define SCAP_INVALID_BUFFER_HANDLE ((scap_buffer_t)0xFFFFFFFF)

#ifdef __cplusplus
}
#endif

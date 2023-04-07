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

#ifndef SCAP_HANDLE_T
#define SCAP_HANDLE_T void
#endif

#include "engine_handle.h"

struct scap_vtable;

/**
 * Is `driver_api_version` compatible with `required_api_version`?
 */
bool scap_is_api_compatible(unsigned long driver_api_version, unsigned long required_api_version);

/**
 * Apply the `semver` checks on current and required versions.
 */  
bool scap_apply_semver_check(uint32_t current_major, uint32_t current_minor, uint32_t current_patch,
							uint32_t required_major, uint32_t required_minor, uint32_t required_patch);

int32_t check_api_compatibility(const struct scap_vtable* vtable, struct scap_engine_handle engine, char *error);

/**
 * \brief Get the timestamp of boot with subsecond accuracy
 *
 * @param last_err a buffer of SCAP_LASTERR_SIZE for the error message, if any
 * @param boot_time pointer to the result (boot time in nanoseconds since the epoch)
 * @return SCAP_SUCCESS or an error code
 *
 * As opposed to scap_get_boot_time, this function:
 * - is an internal helper, intended only for the engines' use (BPF-based in particular)
 * - doesn't need wide compatibility (only needs to work on systems supporting eBPF)
 * - needs as much accuracy as we can get (otherwise eBPF event timestamps will be wrong)
 */
int32_t scap_get_precise_boot_time(char* last_err, uint64_t *boot_time);

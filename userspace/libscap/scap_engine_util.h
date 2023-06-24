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

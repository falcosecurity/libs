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

void change_interest_for_single_syscall(uint32_t ppm_sc, bool *syscalls_of_interest, bool enable);

/**
 * @brief Takes an array of `ppm_sc_code` from `scap_open_args` and set the
 * interesting syscalls for a specific engine.
 *
 * Please note: This function must be used during the engine initialization.
 *
 * @param oargs pointer to the `scap_open_args` struct.
 * @param syscalls_of_interest pointer to the engine syscalls of interest. 
 */
void init_syscall_of_interest_table(scap_open_args *oargs, bool *syscalls_of_interest);

/**
 * @brief Takes an array of interesting tracepoints from `scap_open_args` and set the
 * interesting tracepoints for a specific engine.
 *
 * Please note: This function must be used during the engine initialization.
 *
 * @param oargs pointer to the `scap_open_args` struct.
 * @param tracepoints_of_interest pointer to the engine tracepoints of interest. 
 */
void init_tracepoint_of_interest_table(scap_open_args *oargs, bool *tracepoints_of_interest)

int32_t check_api_compatibility(scap_t *handle, char *error);

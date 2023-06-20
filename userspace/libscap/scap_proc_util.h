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

#ifdef __cplusplus
extern "C" {
#endif

typedef struct scap scap_t;
typedef struct scap_fdinfo scap_fdinfo;
typedef struct scap_proclist scap_proclist;
typedef struct scap_threadinfo scap_threadinfo;

/**
 * @brief get information about file descriptors for a thread that was identified by get_threadinfos
 * @param engine wraps the pointer to the engine-specific handle
 * @param tinfo a thread pointer returned by get_threadinfos
 * @param n [out] the number of scap_fdinfo structures returned
 * @param fdinfos [out] an array of scap_fdinfo structures
 * @return SCAP_SUCCESS or a failure code
 *
 */
typedef int32_t (*get_fdinfos_fn)(void* ctx, const scap_threadinfo *tinfo, uint64_t *n, const scap_fdinfo **fdinfos);

// Scan process information from engine vtable
int32_t scap_proc_scan_vtable(char *error, struct scap_proclist *proclist, uint64_t n_tinfos, const scap_threadinfo *tinfos, void* ctx, get_fdinfos_fn get_fdinfos);

#ifdef __cplusplus
};
#endif

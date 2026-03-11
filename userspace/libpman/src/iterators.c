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

#include <libpman.h>
#include <libscap/scap.h>
#include <libscap/strl.h>

#ifdef BPF_ITERATOR_DEBUG

#if defined(BPF_ITERATOR_DEBUG_RAW) || defined(BPF_ITERATOR_DEBUG_PARSED)

#include <libscap/scap_print.h>

#ifdef BPF_ITERATOR_DEBUG_RAW
#define DEBUG_PRINT_EVENT(evt_ptr) scap_print_event(evt_ptr, PRINT_FULL)
#endif  // BPF_ITERATOR_DEBUG_RAW

#ifdef BPF_ITERATOR_DEBUG_PARSED
#define DEBUG_PRINT_THREADINFO(tinfo_ptr) scap_print_threadinfo(tinfo_ptr)
#define DEBUG_PRINT_FDINFO(fdinfo_ptr) scap_print_fdinfo(fdinfo_ptr)
#endif  // BPF_ITERATOR_DEBUG_PARSED

#endif  // defined(BPF_ITERATOR_DEBUG_RAW) || defined(BPF_ITERATOR_DEBUG_PARSED)

#endif  // BPF_ITERATOR_DEBUG

#ifndef DEBUG_PRINT_EVENT
#define DEBUG_PRINT_EVENT(evt_ptr)
#endif

#ifndef DEBUG_PRINT_THREADINFO
#define DEBUG_PRINT_THREADINFO(tinfo_ptr)
#endif

#ifndef DEBUG_PRINT_FDINFO
#define DEBUG_PRINT_FDINFO(fdinfo_ptr)
#endif

int32_t pman_iter_fetch_task(const struct scap_fetch_callbacks *callbacks,
                             const uint32_t tid,
                             scap_threadinfo **tinfo,
                             char *error) {
	return SCAP_NOT_SUPPORTED;
}

int32_t pman_iter_fetch_tasks(const struct scap_fetch_callbacks *callbacks, char *error) {
	return SCAP_NOT_SUPPORTED;
}

int32_t pman_iter_fetch_proc_file(const struct scap_fetch_callbacks *callbacks,
                                  const uint32_t pid,
                                  const uint32_t fd,
                                  char *error) {
	return SCAP_NOT_SUPPORTED;
}

int32_t pman_iter_fetch_proc_files(const struct scap_fetch_callbacks *callbacks,
                                   const uint32_t pid,
                                   const bool must_fetch_sockets,
                                   uint64_t *num_files_fetched,
                                   char *error) {
	return SCAP_NOT_SUPPORTED;
}

int32_t pman_iter_fetch_procs_files(const struct scap_fetch_callbacks *callbacks, char *error) {
	return SCAP_NOT_SUPPORTED;
}

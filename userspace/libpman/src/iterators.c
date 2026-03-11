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

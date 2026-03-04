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
#include <libscap/scap.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum scap_print_evt_info {
	PRINT_HEADER = 0,
	PRINT_HEADER_LENGTHS,
	PRINT_FULL,
} scap_print_evt_info;
void scap_print_event(scap_evt *ev, scap_print_evt_info i);
void scap_print_threadinfo(const scap_threadinfo *tinfo);
void scap_print_fdinfo(const scap_fdinfo *fdinfo);

#ifdef __cplusplus
}
#endif

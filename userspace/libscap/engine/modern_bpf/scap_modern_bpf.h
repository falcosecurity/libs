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

#include <stdbool.h>
#include <stdlib.h>
#include <driver/ppm_events_public.h>
#include <libscap/scap_open.h>
#include <libscap/engine/modern_bpf/modern_bpf_public.h>

struct scap;

struct modern_bpf_engine
{
	unsigned long m_retry_us; /* Microseconds to wait if all ring buffers are empty */
	char* m_lasterr; /* Last error caught by the engine */
	interesting_ppm_sc_set curr_sc_set; /* current ppm_sc */
	uint64_t m_api_version;
	uint64_t m_schema_version;
	bool capturing;
	uint64_t m_flags;
};

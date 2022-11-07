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
#include <stdlib.h>
#include "../../../../driver/ppm_events_public.h"

struct scap;

struct modern_bpf_engine
{
	size_t m_num_cpus;
	unsigned long m_retry_us;
	char* m_lasterr;
};

#define SCAP_HANDLE_T struct modern_bpf_engine

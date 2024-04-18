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

#include <stdint.h>
#include <libscap/ringbuffer/devset.h>
#include <libscap/scap_open.h>
#include <libscap/metrics_v2.h>
#include <libscap/engine/kmod/scap_kmod_stats.h>


struct kmod_engine
{
	struct scap_device_set m_dev_set;
	char* m_lasterr;
	interesting_ppm_sc_set curr_sc_set;
	uint64_t m_api_version;
	uint64_t m_schema_version;
	bool capturing;
	metrics_v2 m_stats[KMOD_MAX_KERNEL_COUNTERS_STATS];
};

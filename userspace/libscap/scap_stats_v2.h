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

#ifdef __cplusplus
extern "C" {
#endif



//
// Limits for scap_stats_v2 metric name
//
#define STATS_NAME_MAX 512

//
// scap_stats_v2 flags
//
#define PPM_SCAP_STATS_KERNEL_COUNTERS (1 << 0)
#define PPM_SCAP_STATS_LIBBPF_STATS (1 << 1)
#define PPM_SCAP_STATS_RESOURCE_UTILIZATION (1 << 2)
#define PPM_SCAP_STATS_STATE_COUNTERS (1 << 3)

typedef union scap_stats_v2_value {
	uint32_t u32;
	int32_t s32;
	uint64_t u64;
	int64_t s64;
	double d;
	float f;
	int i;
}scap_stats_v2_value;

typedef enum scap_stats_v2_value_type{
	STATS_VALUE_TYPE_U32,
	STATS_VALUE_TYPE_S32,
	STATS_VALUE_TYPE_U64,
	STATS_VALUE_TYPE_S64,
	STATS_VALUE_TYPE_D,
	STATS_VALUE_TYPE_F,
	STATS_VALUE_TYPE_I,
}scap_stats_v2_value_type;

typedef enum scap_stats_v2_value_unit{
	STATS_VALUE_UNIT_COUNT,
	STATS_VALUE_UNIT_PERC,
	STATS_VALUE_UNIT_MEMORY_BYTES,
	STATS_VALUE_UNIT_MEMORY_KILOBYTES,
}scap_stats_v2_value_unit;

typedef enum scap_stats_v2_metric_type{
	STATS_VALUE_MONOTONIC,
	STATS_VALUE_NON_MONOTONIC_CURRENT,
}scap_stats_v2_metric_type;

/*!
  \brief Statistics about an in progress capture (including counters and libbpf stats, compare to `bpftool prog show` CLI).
*/
typedef struct scap_stats_v2
{
	/* Metadata */
	char name[STATS_NAME_MAX];
	uint32_t flags;
	scap_stats_v2_metric_type metric_type;
	/* Stats values */
	scap_stats_v2_value value;
	scap_stats_v2_value_type type;
	scap_stats_v2_value_unit unit;
}scap_stats_v2;

#ifdef __cplusplus
}
#endif

// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

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
// Limits for metrics_v2 metric name
//
#define METRIC_NAME_MAX 512

//
// metrics_v2 flags
//
#define METRICS_V2_KERNEL_COUNTERS (1 << 0)
#define METRICS_V2_LIBBPF_STATS (1 << 1)
#define METRICS_V2_RESOURCE_UTILIZATION (1 << 2)
#define METRICS_V2_STATE_COUNTERS (1 << 3)
#define METRICS_V2_RULE_COUNTERS (1 << 4)
#define METRICS_V2_MISC (1 << 5)
#define METRICS_V2_PLUGINS (1 << 6)

typedef union metrics_v2_value {
	uint32_t u32;
	int32_t s32;
	uint64_t u64;
	int64_t s64;
	double d;
	float f;
	int i;
} metrics_v2_value;

typedef enum metrics_v2_value_type{
	METRIC_VALUE_TYPE_U32,
	METRIC_VALUE_TYPE_S32,
	METRIC_VALUE_TYPE_U64,
	METRIC_VALUE_TYPE_S64,
	METRIC_VALUE_TYPE_D,
	METRIC_VALUE_TYPE_F,
	METRIC_VALUE_TYPE_I,
	METRIC_VALUE_TYPE_MAX,
} metrics_v2_value_type;

typedef enum metrics_v2_value_unit{
	METRIC_VALUE_UNIT_COUNT,
	METRIC_VALUE_UNIT_RATIO,
	METRIC_VALUE_UNIT_PERC,
	METRIC_VALUE_UNIT_MEMORY_BYTES,
	METRIC_VALUE_UNIT_MEMORY_KIBIBYTES,
	METRIC_VALUE_UNIT_MEMORY_MEGABYTES,
	METRIC_VALUE_UNIT_TIME_NS,
	METRIC_VALUE_UNIT_TIME_S,
	METRIC_VALUE_UNIT_TIME_NS_COUNT,
	METRIC_VALUE_UNIT_TIME_S_COUNT,
	METRIC_VALUE_UNIT_TIME_TIMESTAMP_NS,
	METRIC_VALUE_UNIT_MAX,
} metrics_v2_value_unit;

typedef enum metrics_v2_metric_type{
	METRIC_VALUE_METRIC_TYPE_MONOTONIC,
	METRIC_VALUE_METRIC_TYPE_NON_MONOTONIC_CURRENT,
	METRIC_VALUE_METRIC_TYPE_MAX,
} metrics_v2_metric_type;

/*!
  \brief Metrics schema, used for libscap and libsinsp metrics about an in progress capture.
*/
typedef struct metrics_v2
{
	/* Metric metadata */
	char name[METRIC_NAME_MAX];
	uint32_t flags;
	metrics_v2_metric_type metric_type;
	/* Metric value */
	metrics_v2_value value;
	metrics_v2_value_type type;
	metrics_v2_value_unit unit;
} metrics_v2;

#ifdef __cplusplus
}
#endif

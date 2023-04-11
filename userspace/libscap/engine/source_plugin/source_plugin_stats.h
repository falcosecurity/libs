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

typedef enum source_plugin_counters_stats {
	N_EVTS = 0,
	MAX_SOURCE_PLUGIN_COUNTERS_STATS,
}source_plugin_counters_stats;

static const char * const source_plugin_counters_stats_names[] = {
	[N_EVTS] = "n_evts",
};

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

#include <stdint.h>
#include "plugin_info.h"

struct scap;

struct source_plugin_engine
{
	char* m_lasterr;

	scap_source_plugin* m_input_plugin;
	uint8_t* m_input_plugin_evt_storage;
	uint32_t m_input_plugin_evt_storage_len;

	// The number of items held in batch_evts
	uint32_t m_input_plugin_batch_nevts;

	// A set of events returned from next_batch. The array is
	// allocated and must be free()d when done.
	ss_plugin_event* m_input_plugin_batch_evts;

	// The current position into the above arrays (0-indexed),
	// reflecting how many of the above items have been returned
	// via a call to next().
	uint32_t m_input_plugin_batch_idx;

	// The return value from the last call to next_batch().
	ss_plugin_rc m_input_plugin_last_batch_res;

};

#define SCAP_HANDLE_T struct source_plugin_engine

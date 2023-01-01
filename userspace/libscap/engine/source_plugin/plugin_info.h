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

#include "../plugin/plugin_api.h"

//
// Small C interface that is passed down to libscap
// and is used as a plugin event source.
//
typedef struct
{
	uint32_t id;
	const char *name;
	ss_plugin_t *state;
	ss_instance_t *handle;

	ss_instance_t* (*open)(ss_plugin_t* s, const char* params, ss_plugin_rc* rc);
	void (*close)(ss_plugin_t* s, ss_instance_t* h);
	ss_plugin_rc (*next_batch)(ss_plugin_t* s, ss_instance_t* h, uint32_t *nevts, ss_plugin_event **evts);
	const char *(*get_last_error)(ss_plugin_t *s);
} scap_source_plugin;
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

#include <driver/ppm_events_public.h>
#include "sample_table.h"
#include "test_plugins.h"

#include <atomic>
#include <memory>

struct plugin_state {
	std::string lasterr;
	ss_plugin_owner_t* owner;
	ss_plugin_routine_vtable routine_vtable;

	uint8_t step = 1;
	std::atomic<bool> flag = true;
	ss_plugin_routine_t* routine;
};

static const char* plugin_get_required_api_version() {
	return PLUGIN_API_VERSION_STR;
}

static const char* plugin_get_version() {
	return "0.1.0";
}

static const char* plugin_get_name() {
	return "sample_routines";
}

static const char* plugin_get_description() {
	return "some desc";
}

static const char* plugin_get_contact() {
	return "some contact";
}

static const char* plugin_get_parse_event_sources() {
	return "[\"syscall\"]";
}

static uint16_t* plugin_get_parse_event_types(uint32_t* num_types, ss_plugin_t* s) {
	static uint16_t types[] = {
	        PPME_SYSCALL_OPEN_E,
	};
	*num_types = sizeof(types) / sizeof(uint16_t);
	return &types[0];
}

static ss_plugin_t* plugin_init(const ss_plugin_init_input* in, ss_plugin_rc* rc) {
	*rc = SS_PLUGIN_SUCCESS;
	plugin_state* ret = new plugin_state();

	ret->owner = in->owner;

	return ret;
}

static void plugin_destroy(ss_plugin_t* s) {
	delete((plugin_state*)s);
}

static const char* plugin_get_last_error(ss_plugin_t* s) {
	return ((plugin_state*)s)->lasterr.c_str();
}

static ss_plugin_bool test_routine(ss_plugin_t* s, ss_plugin_routine_state_t* i) {
	bool flag = *(bool*)i;

	// this routine keeps running while flag is true
	return flag;
}

static ss_plugin_bool do_nothing(ss_plugin_t* s, ss_plugin_routine_state_t* i) {
	// this routine always keeps running
	return true;
}

static ss_plugin_rc plugin_parse_event(ss_plugin_t* s,
                                       const ss_plugin_event_input* ev,
                                       const ss_plugin_event_parse_input* in) {
	plugin_state* ps = (plugin_state*)s;

	switch(ps->step) {
	case 1:
		ps->routine = ps->routine_vtable.subscribe(ps->owner,
		                                           do_nothing,
		                                           (ss_plugin_routine_state_t*)&ps->flag);
		break;
	case 2:
		ps->routine_vtable.unsubscribe(ps->owner, ps->routine);
		break;
	case 3:
		ps->routine = ps->routine_vtable.subscribe(ps->owner,
		                                           test_routine,
		                                           (ss_plugin_routine_state_t*)&ps->flag);
		break;
	case 4:
		ps->flag = false;
		break;
	default:
		break;
	}

	ps->step++;

	return SS_PLUGIN_SUCCESS;
}

static ss_plugin_rc plugin_capture_open(ss_plugin_t* s, const ss_plugin_capture_listen_input* i) {
	plugin_state* ps = (plugin_state*)s;
	ps->routine_vtable.subscribe = i->routine->subscribe;
	ps->routine_vtable.unsubscribe = i->routine->unsubscribe;

	ps->routine_vtable.subscribe(ps->owner, do_nothing, (ss_plugin_routine_state_t*)&ps->flag);

	return SS_PLUGIN_SUCCESS;
}

static ss_plugin_rc plugin_capture_close(ss_plugin_t* s, const ss_plugin_capture_listen_input* i) {
	return SS_PLUGIN_SUCCESS;
}

void get_plugin_api_sample_routines(plugin_api& out) {
	memset(&out, 0, sizeof(plugin_api));
	out.get_required_api_version = plugin_get_required_api_version;
	out.get_version = plugin_get_version;
	out.get_description = plugin_get_description;
	out.get_contact = plugin_get_contact;
	out.get_name = plugin_get_name;
	out.get_last_error = plugin_get_last_error;
	out.init = plugin_init;
	out.destroy = plugin_destroy;
	out.get_parse_event_sources = plugin_get_parse_event_sources;
	out.get_parse_event_types = plugin_get_parse_event_types;
	out.parse_event = plugin_parse_event;
	out.capture_open = plugin_capture_open;
	out.capture_close = plugin_capture_close;
}

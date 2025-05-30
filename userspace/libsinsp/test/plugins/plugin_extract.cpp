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

#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <vector>

#include <driver/ppm_events_public.h>

#include "test_plugins.h"

namespace {

/**
 * Example of plugin implementing only the field extraction capability, which:
 * - Is compatible with the "sample" event source only
 * - Extracts a simple field containing the string inside the events' payload
 */
struct plugin_state {
	std::string lasterr;
	std::string strstorage;
	std::vector<uint32_t> offsets;
	std::vector<uint32_t> lengths;
	const char* strptr;
	std::vector<uint16_t> event_types;
	ss_plugin_owner_t* owner;
	ss_plugin_log_fn_t log;
};

const char* plugin_get_required_api_version() {
	return PLUGIN_API_VERSION_STR;
}

const char* plugin_get_version() {
	return "0.1.0";
}

const char* plugin_get_name() {
	return "sample_plugin_extract";
}

const char* plugin_get_description() {
	return "some desc";
}

const char* plugin_get_contact() {
	return "some contact";
}

const char* plugin_get_fields() {
	return "["
	       "{\"type\": \"string\", \"name\": \"sample.hello\", \"desc\": \"A constant hello world "
	       "string\", \"addOutput\": true}"
	       "]";
}

const char* plugin_get_extract_event_sources() {
	return "[\"sample\"]";
}

uint16_t* plugin_get_extract_event_types(uint32_t* num_types, ss_plugin_t* s) {
	auto ps = reinterpret_cast<plugin_state*>(s);
	if(!ps->event_types.empty()) {
		*num_types = (uint32_t)ps->event_types.size();
		return ps->event_types.data();
	}

	static uint16_t* types = {};
	*num_types = 0;
	return types;
}

ss_plugin_t* plugin_init(const ss_plugin_init_input* in, ss_plugin_rc* rc) {
	auto ret = new plugin_state();

	// save logger and owner in the state
	ret->log = in->log_fn;
	ret->owner = in->owner;

	ret->log(ret->owner, NULL, "initializing plugin...", SS_PLUGIN_LOG_SEV_INFO);

	// init config may indicate the comma-separated, event-types to filter
	std::string cfg = in->config;
	if(!cfg.empty()) {
		if(cfg.back() != ',') {
			cfg += ",";
		}
		std::string val;
		std::stringstream test(cfg);
		while(std::getline(test, val, ',')) {
			auto v = std::atoi(val.c_str());
			if(v == 0) {
				ret->lasterr = "invalid init config string: " + cfg;
				return ret;
			}
			ret->event_types.push_back((uint16_t)v);
		}
	}

	*rc = SS_PLUGIN_SUCCESS;
	return ret;
}

void plugin_destroy(ss_plugin_t* s) {
	auto ps = reinterpret_cast<plugin_state*>(s);
	ps->log(ps->owner, NULL, "destroying plugin...", SS_PLUGIN_LOG_SEV_INFO);

	delete ps;
}

const char* plugin_get_last_error(ss_plugin_t* s) {
	return ((plugin_state*)s)->lasterr.c_str();
}

ss_plugin_rc plugin_extract_fields(ss_plugin_t* s,
                                   const ss_plugin_event_input* ev,
                                   const ss_plugin_field_extract_input* in) {
	auto ps = reinterpret_cast<plugin_state*>(s);

	if(in->value_offsets) {
		ps->offsets.resize(in->num_fields);
		ps->lengths.resize(in->num_fields);
	}

	for(uint32_t i = 0; i < in->num_fields; i++) {
		switch(in->fields[i].field_id) {
		case 0:  // test.hello
		{
			ps->strstorage = "hello world";
			ps->strptr = ps->strstorage.c_str();
			static uint32_t res_start = 0;
			static uint32_t res_length = ps->strstorage.size();
			in->fields[i].res.str = &ps->strptr;
			in->fields[i].res_len = 1;
			if(in->value_offsets) {
				ps->offsets[i] = PLUGIN_EVENT_PAYLOAD_OFFSET + res_start;
				ps->lengths[i] = res_length;
			}
		} break;
		default:
			in->fields[i].res_len = 0;
			return SS_PLUGIN_FAILURE;
		}
	}
	if(in->value_offsets) {
		in->value_offsets->start = ps->offsets.data();
		in->value_offsets->length = ps->lengths.data();
	}
	return SS_PLUGIN_SUCCESS;
}

ss_plugin_rc plugin_set_config(ss_plugin_t* s, const ss_plugin_set_config_input* i) {
	auto ps = reinterpret_cast<plugin_state*>(s);
	ps->log(ps->owner, NULL, "new config!", SS_PLUGIN_LOG_SEV_INFO);

	return SS_PLUGIN_SUCCESS;
}

}  // anonymous namespace

void get_plugin_api_sample_plugin_extract(plugin_api& out) {
	memset(&out, 0, sizeof(plugin_api));
	out.get_required_api_version = plugin_get_required_api_version;
	out.get_version = plugin_get_version;
	out.get_description = plugin_get_description;
	out.get_contact = plugin_get_contact;
	out.get_name = plugin_get_name;
	out.get_last_error = plugin_get_last_error;
	out.init = plugin_init;
	out.destroy = plugin_destroy;
	out.get_fields = plugin_get_fields;
	out.get_extract_event_sources = plugin_get_extract_event_sources;
	out.get_extract_event_types = plugin_get_extract_event_types;
	out.extract_fields = plugin_extract_fields;
	out.set_config = plugin_set_config;
}

// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2025 The Falco Authors.

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
#include <memory>
#include <string>
#include <vector>
#include <json/json.h>

#include <driver/ppm_events_public.h>

#include "test_plugins.h"

namespace {

/**
 * Test plugin for schema version validation
 */
struct plugin_state {
	std::string lasterr = "";
	std::string required_schema_version = "";
	std::vector<uint16_t> event_types = {};
};

const char* plugin_get_required_api_version() {
	return PLUGIN_API_VERSION_STR;
}

const char* plugin_get_version() {
	return "0.1.0";
}

const char* plugin_get_name() {
	return "schema_version_test";
}

const char* plugin_get_description() {
	return "Test plugin for schema version validation";
}

const char* plugin_get_contact() {
	return "test contact";
}

const char* plugin_get_required_event_schema_version(ss_plugin_t* s) {
	if(s == NULL) {
		return NULL;  // Default to 3.0.0
	}

	plugin_state* state = (plugin_state*)s;
	if(state->required_schema_version.empty()) {
		return NULL;  // Default to 3.0.0
	}

	return state->required_schema_version.c_str();
}

const char* plugin_get_init_schema(ss_plugin_schema_type* schema_type) {
	*schema_type = SS_PLUGIN_SCHEMA_JSON;
	return R"({
		"type": "object",
		"properties": {
			"required_schema_version": {
				"type": "string",
				"description": "Required schema version for testing"
			},
			"event_types": {
				"type": "array",
				"description": "Event types for testing",
				"items": {
					"type": "integer"
				}
			}
		}
	})";
}

ss_plugin_t* plugin_init(const ss_plugin_init_input* input, ss_plugin_rc* rc) {
	plugin_state* state = new plugin_state();
	*rc = SS_PLUGIN_SUCCESS;

	Json::Value root;
	Json::CharReaderBuilder builder;
	const std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
	std::string err;

	// check that the output is valid json
	bool json_parse =
	        reader->parse(input->config, input->config + strlen(input->config), &root, &err);
	if(!json_parse) {
		*rc = SS_PLUGIN_FAILURE;
		return NULL;
	}

	// Parse config to get required schema version
	if(!root["required_schema_version"].empty()) {
		// Simple parsing for test purposes
		state->required_schema_version = root["required_schema_version"].asString();
	}

	if(root["event_types"].isArray()) {
		for(const auto& event_type : root["event_types"]) {
			state->event_types.push_back(event_type.asInt());
		}
	}

	return (ss_plugin_t*)state;
}

void plugin_destroy(ss_plugin_t* s) {
	if(s != NULL) {
		delete(plugin_state*)s;
	}
}

const char* plugin_get_last_error(ss_plugin_t* s) {
	if(s == NULL) {
		return "Plugin state is NULL";
	}

	plugin_state* state = (plugin_state*)s;
	if(state->lasterr.empty()) {
		return NULL;  // No error
	}

	return state->lasterr.c_str();
}

// Field extraction capability
const char* plugin_event_sources_syscall() {
	return R"(["syscall"])";
}

const char* plugin_event_sources_foo() {
	return R"(["foo"])";
}

uint16_t* plugin_get_event_types(uint32_t* numtypes, ss_plugin_t* s) {
	auto state = (plugin_state*)s;
	*numtypes = state->event_types.size();
	return state->event_types.data();
}

ss_plugin_rc plugin_extract_fields(ss_plugin_t* s,
                                   const ss_plugin_event_input* ev,
                                   const ss_plugin_field_extract_input* in) {
	// Nothing to extract
	return SS_PLUGIN_SUCCESS;
}

const char* plugin_extract_get_fields() {
	return R"(
[
	{
		"type": "string",
		"name": "foo.bar",
		"desc": "A constant hello world string",
		"addOutput": true
	}
]
)";
}

ss_plugin_rc plugin_parse_event(ss_plugin_t* s,
                                const ss_plugin_event_input* ev,
                                const ss_plugin_event_parse_input* in) {
	// Nothing to parse
	return SS_PLUGIN_SUCCESS;
}

}  // namespace

void get_plugin_api_sample_extract_schema_version(plugin_api& out) {
	memset(&out, 0, sizeof(out));
	out.get_required_api_version = plugin_get_required_api_version;
	out.get_version = plugin_get_version;
	out.get_name = plugin_get_name;
	out.get_description = plugin_get_description;
	out.get_contact = plugin_get_contact;
	out.get_required_event_schema_version = plugin_get_required_event_schema_version;
	out.get_init_schema = plugin_get_init_schema;
	out.init = plugin_init;
	out.destroy = plugin_destroy;
	out.get_last_error = plugin_get_last_error;
	out.get_extract_event_sources = plugin_event_sources_syscall;
	out.get_extract_event_types = plugin_get_event_types;
	out.extract_fields = plugin_extract_fields;
	out.get_fields = plugin_extract_get_fields;
}

void get_plugin_api_sample_parse_schema_version(plugin_api& out) {
	memset(&out, 0, sizeof(out));
	out.get_required_api_version = plugin_get_required_api_version;
	out.get_version = plugin_get_version;
	out.get_name = plugin_get_name;
	out.get_description = plugin_get_description;
	out.get_contact = plugin_get_contact;
	out.get_required_event_schema_version = plugin_get_required_event_schema_version;
	out.get_init_schema = plugin_get_init_schema;
	out.init = plugin_init;
	out.destroy = plugin_destroy;
	out.get_last_error = plugin_get_last_error;
	out.get_parse_event_sources = plugin_event_sources_syscall;
	out.get_parse_event_types = plugin_get_event_types;
	out.parse_event = plugin_parse_event;
}

void get_plugin_api_sample_no_required_schema_version(plugin_api& out) {
	memset(&out, 0, sizeof(out));
	out.get_required_api_version = plugin_get_required_api_version;
	out.get_version = plugin_get_version;
	out.get_name = plugin_get_name;
	out.get_description = plugin_get_description;
	out.get_contact = plugin_get_contact;
	out.get_init_schema = plugin_get_init_schema;
	out.init = plugin_init;
	out.destroy = plugin_destroy;
	out.get_last_error = plugin_get_last_error;
	out.get_parse_event_sources = plugin_event_sources_syscall;
	out.get_parse_event_types = plugin_get_event_types;
	out.parse_event = plugin_parse_event;
}

void get_plugin_api_sample_custom_event_sources(plugin_api& out) {
	memset(&out, 0, sizeof(out));
	out.get_required_api_version = plugin_get_required_api_version;
	out.get_version = plugin_get_version;
	out.get_name = plugin_get_name;
	out.get_description = plugin_get_description;
	out.get_contact = plugin_get_contact;
	out.get_required_event_schema_version = plugin_get_required_event_schema_version;
	out.get_init_schema = plugin_get_init_schema;
	out.init = plugin_init;
	out.destroy = plugin_destroy;
	out.get_last_error = plugin_get_last_error;
	out.get_parse_event_sources = plugin_event_sources_foo;
	out.get_parse_event_types = plugin_get_event_types;
	out.parse_event = plugin_parse_event;
}

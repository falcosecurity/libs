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

#include <gtest/gtest.h>

#include <sinsp_with_test_input.h>
#include "test_utils.h"

const char* mock_plugin_get_version()
{
	return "0.1.0";
}

const char* mock_plugin_get_required_api_version()
{
	return PLUGIN_API_VERSION_STR;
}

static const char* mock_plugin_get_name()
{
	return "sample_plugin";
}

const char* mock_plugin_get_description()
{
	return "some sample plugin";
}

const char* mock_plugin_get_contact()
{
	return "some contact";
}

static uint32_t mock_plugin_get_id()
{
	return 999;
}

static const char* mock_plugin_get_event_source()
{
	return "sample_source";
}

static ss_plugin_t* mock_plugin_init(const ss_plugin_init_input *input, ss_plugin_rc *rc)
{
	*rc = SS_PLUGIN_SUCCESS;
	return NULL;
}

static void mock_plugin_destroy(ss_plugin_t* p)
{
}

static const char* mock_plugin_get_last_error(ss_plugin_t* s)
{
	return NULL;
}

static ss_instance_t* mock_plugin_open(ss_plugin_t* s, const char* params, ss_plugin_rc* rc)
{
	*rc = SS_PLUGIN_FAILURE;
	return NULL;
}

static void mock_plugin_close(ss_plugin_t* s, ss_instance_t* i)
{
}

static ss_plugin_rc mock_plugin_next_batch(ss_plugin_t* s, ss_instance_t* i, uint32_t *nevts, ss_plugin_event ***evts)
{
	*nevts = 0;
	return SS_PLUGIN_EOF;
}

static void set_mock_plugin_api(plugin_api& api)
{
	memset(&api, 0, sizeof(plugin_api));
	api.get_required_api_version = mock_plugin_get_required_api_version;
	api.get_version = mock_plugin_get_version;
	api.get_description = mock_plugin_get_description;
	api.get_contact = mock_plugin_get_contact;
	api.get_name = mock_plugin_get_name;
	api.get_last_error = mock_plugin_get_last_error;
	api.init = mock_plugin_init;
	api.destroy = mock_plugin_destroy;
	api.get_id = mock_plugin_get_id;
	api.get_event_source = mock_plugin_get_event_source;
	api.open = mock_plugin_open;
	api.close = mock_plugin_close;
	api.next_batch = mock_plugin_next_batch;
}

TEST_F(sinsp_with_test_input, event_sources)
{
	sinsp_evt* evt = NULL;
	size_t syscall_source_idx = 0; // the "syscall" evt source is always the first one
	std::string syscall_source_name = sinsp_syscall_event_source_name;
	const char sample_plugin_evtdata[256] = "hello world";
	auto plugindata = scap_const_sized_buffer{&sample_plugin_evtdata, strlen(sample_plugin_evtdata) + 1};

	add_default_init_thread();
	open_inspector();

	// create and register a mock plugin
	plugin_api mock_api;
	set_mock_plugin_api(mock_api);
	m_inspector.register_plugin(&mock_api);

	// regular events have the "syscall" event source
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_X, 6, (uint64_t)3, "/tmp/the_file", PPM_O_RDWR, 0, 5, (uint64_t)123);
	ASSERT_EQ(evt->get_type(), PPME_SYSCALL_OPEN_X);
	ASSERT_EQ(evt->get_source_idx(), syscall_source_idx);
	ASSERT_EQ(std::string(evt->get_source_name()), syscall_source_name);
	ASSERT_EQ(get_field_as_string(evt, "evt.source"), syscall_source_name);
	ASSERT_EQ(get_field_as_string(evt, "evt.is_async"), "false");
	ASSERT_FALSE(field_has_value(evt, "evt.asynctype"));

	// metaevents have the "syscall" event source
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_CONTAINER_JSON_E, 1, "{\"value\": 1}");
	ASSERT_EQ(evt->get_type(), PPME_CONTAINER_JSON_E);
	ASSERT_EQ(evt->get_source_idx(), syscall_source_idx);
	ASSERT_EQ(std::string(evt->get_source_name()), syscall_source_name);
	ASSERT_EQ(get_field_as_string(evt, "evt.source"), syscall_source_name);
	ASSERT_EQ(get_field_as_string(evt, "evt.is_async"), "true");
	ASSERT_EQ(get_field_as_string(evt, "evt.asynctype"), "container");

	// events coming from unknown plugins should have no event source
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_PLUGINEVENT_E, 2, (uint32_t) 1, plugindata);
	ASSERT_EQ(evt->get_type(), PPME_PLUGINEVENT_E);
	ASSERT_EQ(evt->get_source_idx(), sinsp_no_event_source_idx);
	ASSERT_EQ(evt->get_source_name(), sinsp_no_event_source_name);
	ASSERT_FALSE(field_has_value(evt, "evt.source"));
	ASSERT_EQ(get_field_as_string(evt, "evt.is_async"), "false");
	ASSERT_FALSE(field_has_value(evt, "evt.asynctype"));

	// events coming from registered plugins should have their event source
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_PLUGINEVENT_E, 2, (uint32_t) 999, plugindata);
	ASSERT_EQ(evt->get_type(), PPME_PLUGINEVENT_E);
	ASSERT_EQ(evt->get_source_idx(), syscall_source_idx + 1);
	ASSERT_EQ(std::string(evt->get_source_name()), std::string(mock_plugin_get_event_source()));
	ASSERT_EQ(get_field_as_string(evt, "evt.source"), std::string(mock_plugin_get_event_source()));
	ASSERT_EQ(get_field_as_string(evt, "evt.is_async"), "false");
	ASSERT_FALSE(field_has_value(evt, "evt.asynctype"));

	// async events with no plugin ID should have "syscall" source
	auto asyncname = "sampleasync";
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_ASYNCEVENT_E, 3, (uint32_t) 0, asyncname, plugindata);
	ASSERT_EQ(evt->get_type(), PPME_ASYNCEVENT_E);
	ASSERT_EQ(evt->get_source_idx(), syscall_source_idx);
	ASSERT_EQ(std::string(evt->get_source_name()), syscall_source_name);
	ASSERT_EQ(get_field_as_string(evt, "evt.source"), syscall_source_name);
	ASSERT_EQ(get_field_as_string(evt, "evt.is_async"), "true");
	ASSERT_EQ(get_field_as_string(evt, "evt.asynctype"), "sampleasync");
	ASSERT_EQ(get_field_as_string(evt, "evt.type"), "sampleasync");

	// async events with a registered plugin ID should have the plugin's event source
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_ASYNCEVENT_E, 3, (uint32_t) 999, asyncname, plugindata);
	ASSERT_EQ(evt->get_type(), PPME_ASYNCEVENT_E);
	ASSERT_EQ(evt->get_source_idx(), syscall_source_idx + 1);
	ASSERT_EQ(std::string(evt->get_source_name()), std::string(mock_plugin_get_event_source()));
	ASSERT_EQ(get_field_as_string(evt, "evt.source"), std::string(mock_plugin_get_event_source()));
	ASSERT_EQ(get_field_as_string(evt, "evt.is_async"), "true");
	ASSERT_EQ(get_field_as_string(evt, "evt.asynctype"), "sampleasync");
	ASSERT_EQ(get_field_as_string(evt, "evt.type"), "sampleasync");

	// async events with unknown plugin ID should have unknown event source
	// async events with a registered plugin ID should have the plugin's event source
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_ASYNCEVENT_E, 3, (uint32_t) 1, asyncname, plugindata);
	ASSERT_EQ(evt->get_type(), PPME_ASYNCEVENT_E);
	ASSERT_EQ(evt->get_source_idx(), sinsp_no_event_source_idx);
	ASSERT_EQ(evt->get_source_name(), sinsp_no_event_source_name);
	ASSERT_FALSE(field_has_value(evt, "evt.source"));
	ASSERT_EQ(get_field_as_string(evt, "evt.is_async"), "true");
	ASSERT_EQ(get_field_as_string(evt, "evt.asynctype"), "sampleasync");
	ASSERT_EQ(get_field_as_string(evt, "evt.type"), "sampleasync");
}

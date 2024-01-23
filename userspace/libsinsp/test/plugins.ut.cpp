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
#include <libsinsp/plugin.h>

#include <sinsp_with_test_input.h>
#include "test_utils.h"
#include "plugins/test_plugins.h"

static std::shared_ptr<sinsp_plugin> register_plugin_api(
		sinsp* i,
		plugin_api& api,
		const std::string& initcfg = "")
{
	std::string err;
	auto pl = i->register_plugin(&api);
	if (!pl->init(initcfg, err))
	{
		throw sinsp_exception(err);
	}
	return pl;
}

static std::shared_ptr<sinsp_plugin> register_plugin(
		sinsp* i,
		std::function<void(plugin_api&)> constructor,
		const std::string& initcfg = "")
{
	plugin_api api;
	constructor(api);
	return register_plugin_api(i, api, initcfg);
}

static void add_plugin_filterchecks(
		sinsp* i,
		std::shared_ptr<sinsp_plugin> p,
		const std::string& src,
		filter_check_list& fl)
{
	if (p->caps() & CAP_EXTRACTION
		&& sinsp_plugin::is_source_compatible(p->extract_event_sources(), src))
	{
		fl.add_filter_check(i->new_generic_filtercheck());
		fl.add_filter_check(sinsp_plugin::new_filtercheck(p));
	}
}

TEST(plugins, broken_source_capability)
{
	plugin_api api;
	auto inspector = std::unique_ptr<sinsp>(new sinsp());
	get_plugin_api_sample_plugin_source(api);

	// The example plugin has id 999 so `!= 0`. For this reason,
	// the event source name should be different from "syscall"
	api.get_id = [](){ return (uint32_t)999; };
	api.get_event_source = [](){ return sinsp_syscall_event_source_name; };
	ASSERT_ANY_THROW(register_plugin_api(inspector.get(), api));

	// `get_event_source` is implemented so also `get_id` should be implemented
	api.get_id = NULL;
	api.get_event_source = [](){ return sinsp_syscall_event_source_name; };
	ASSERT_ANY_THROW(register_plugin_api(inspector.get(), api));

	// Now both methods are NULL so we are ok!
	api.get_id = NULL;
	api.get_event_source = NULL;
	ASSERT_NO_THROW(register_plugin_api(inspector.get(), api));

	// restore inspector and source API
	inspector.reset(new sinsp());
	get_plugin_api_sample_plugin_source(api);

	// `open`, `close`, `next_batch` must be all defined to provide source capability
	api.open = NULL;
	ASSERT_ANY_THROW(register_plugin_api(inspector.get(), api));
	api.close = NULL;
	ASSERT_ANY_THROW(register_plugin_api(inspector.get(), api));
	api.next_batch = NULL;

	// Now that all the 3 methods are NULL the plugin has no more capabilities
	// so we should throw an exception because every plugin should implement at least one
	// capability
	ASSERT_ANY_THROW(register_plugin_api(inspector.get(), api));
}

TEST(plugins, broken_extract_capability)
{
	plugin_api api;
	auto inspector = std::unique_ptr<sinsp>(new sinsp());
	get_plugin_api_sample_plugin_extract(api);

	// `extract_fields` is defined but `get_fields` no
	api.get_fields = NULL;
	ASSERT_ANY_THROW(register_plugin_api(inspector.get(), api));

	// Both NULL, the plugin has no capabilities
	api.get_fields = NULL;
	api.extract_fields = NULL;
	ASSERT_ANY_THROW(register_plugin_api(inspector.get(), api));
}

TEST(plugins, broken_parsing_capability)
{
	plugin_api api;
	auto inspector = std::unique_ptr<sinsp>(new sinsp());
	get_plugin_api_sample_syscall_parse(api);

	// The plugin has no capabilities
	api.parse_event = NULL;
	ASSERT_ANY_THROW(register_plugin_api(inspector.get(), api));
}

TEST(plugins, broken_async_capability)
{
	plugin_api api;
	auto inspector = std::unique_ptr<sinsp>(new sinsp());
	get_plugin_api_sample_syscall_async(api);

	/* `set_async_event_handler` is defined but `get_async_events` is not */
	api.get_async_events = NULL;
	ASSERT_ANY_THROW(register_plugin_api(inspector.get(), api));

	// Both NULL, the plugin has no capabilities
	api.get_async_events = NULL;
	api.set_async_event_handler = NULL;
	ASSERT_ANY_THROW(register_plugin_api(inspector.get(), api));
}

// scenario: a plugin with field extraction capability compatible with the
// "syscall" event source should be able to extract filter values from
// regular syscall events produced by any scap engine.
TEST_F(sinsp_with_test_input, plugin_syscall_extract)
{
	size_t syscall_source_idx = 0;
	std::string syscall_source_name = sinsp_syscall_event_source_name;

	filter_check_list pl_flist;

	// Register a plugin with source capabilities
	register_plugin(&m_inspector, get_plugin_api_sample_plugin_source);

	// Register a plugin with extraction capabilities
	auto pl = register_plugin(&m_inspector, get_plugin_api_sample_syscall_extract);

	// This plugin tells that it can receive `syscall` events
	add_plugin_filterchecks(&m_inspector, pl, sinsp_syscall_event_source_name, pl_flist);

	// Open the inspector in test mode
	add_default_init_thread();
	open_inspector();

	// should extract legit values for non-ignored event codes
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_E, 3, "/tmp/the_file", PPM_O_RDWR, 0);
	auto evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_X, 6, (uint64_t)3, "/tmp/the_file", PPM_O_RDWR, 0, 5, (uint64_t)123);
	ASSERT_EQ(evt->get_source_idx(), syscall_source_idx);
	ASSERT_EQ(std::string(evt->get_source_name()), syscall_source_name);
	ASSERT_EQ(evt->get_type(), PPME_SYSCALL_OPEN_X);
	ASSERT_EQ(get_field_as_string(evt, "sample.is_open", pl_flist), "1");
	ASSERT_EQ(get_field_as_string(evt, "sample.proc_name", pl_flist), "init");
	ASSERT_FALSE(field_has_value(evt, "sample.open_count", pl_flist));
	ASSERT_FALSE(field_has_value(evt, "sample.evt_count", pl_flist));
	ASSERT_EQ(get_field_as_string(evt, "sample.tick", pl_flist), "false");

	// Here `sample.is_open` should be false
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_INOTIFY_INIT1_X, 2, (int64_t)12, (uint16_t)32);
	ASSERT_EQ(evt->get_source_idx(), syscall_source_idx);
	ASSERT_EQ(std::string(evt->get_source_name()), syscall_source_name);
	ASSERT_EQ(evt->get_type(), PPME_SYSCALL_INOTIFY_INIT1_X);
	ASSERT_EQ(get_field_as_string(evt, "sample.is_open", pl_flist), "0");
	ASSERT_EQ(get_field_as_string(evt, "sample.proc_name", pl_flist), "init");
	ASSERT_FALSE(field_has_value(evt, "sample.open_count", pl_flist));
	ASSERT_FALSE(field_has_value(evt, "sample.evt_count", pl_flist));
	ASSERT_EQ(get_field_as_string(evt, "sample.tick", pl_flist), "false");

	// should extract NULL for ignored event codes
	// `PPME_SYSCALL_OPEN_BY_HANDLE_AT_X` is an ignored event, see plugin_get_extract_event_types
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_BY_HANDLE_AT_X, 4, 4, 5, PPM_O_RDWR, "/tmp/the_file.txt");
	ASSERT_EQ(evt->get_source_idx(), syscall_source_idx);
	ASSERT_EQ(std::string(evt->get_source_name()), syscall_source_name);
	ASSERT_EQ(evt->get_type(), PPME_SYSCALL_OPEN_BY_HANDLE_AT_X);
	ASSERT_FALSE(field_has_value(evt, "sample.is_open", pl_flist));
	ASSERT_FALSE(field_has_value(evt, "sample.proc_name", pl_flist));
	ASSERT_FALSE(field_has_value(evt, "sample.open_count", pl_flist));
	ASSERT_FALSE(field_has_value(evt, "sample.evt_count", pl_flist));
	ASSERT_FALSE(field_has_value(evt, "sample.tick", pl_flist));

	// should extract NULL for unknown event sources
	const char data[2048] = "hello world";
	/* There are no added plugins with id `1` */
	uint64_t unknwon_plugin_id = 1;
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_PLUGINEVENT_E, 2, unknwon_plugin_id, scap_const_sized_buffer{&data, strlen(data) + 1});
	ASSERT_EQ(evt->get_source_idx(), sinsp_no_event_source_idx);
	ASSERT_EQ(evt->get_source_name(), sinsp_no_event_source_name);
	ASSERT_EQ(evt->get_type(), PPME_PLUGINEVENT_E);
	ASSERT_FALSE(field_has_value(evt, "sample.is_open", pl_flist));
	ASSERT_FALSE(field_has_value(evt, "sample.proc_name", pl_flist));
	ASSERT_FALSE(field_has_value(evt, "sample.open_count", pl_flist));
	ASSERT_FALSE(field_has_value(evt, "sample.evt_count", pl_flist));
	ASSERT_FALSE(field_has_value(evt, "sample.tick", pl_flist));

	// should extract NULL for non-compatible event sources
	/* This source plugin generate events with a source that we cannot extract with our plugin */
	uint64_t source_plugin_id = 999;
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_PLUGINEVENT_E, 2, source_plugin_id, scap_const_sized_buffer{&data, strlen(data) + 1});
	ASSERT_EQ(evt->get_source_idx(), 1);
	ASSERT_EQ(std::string(evt->get_source_name()), std::string("sample"));
	ASSERT_EQ(evt->get_type(), PPME_PLUGINEVENT_E);
	ASSERT_FALSE(field_has_value(evt, "sample.is_open", pl_flist));
	ASSERT_FALSE(field_has_value(evt, "sample.proc_name", pl_flist));
	ASSERT_FALSE(field_has_value(evt, "sample.open_count", pl_flist));
	ASSERT_FALSE(field_has_value(evt, "sample.evt_count", pl_flist));
	ASSERT_FALSE(field_has_value(evt, "sample.tick", pl_flist));
}

// scenario: an event sourcing plugin should produce events of "syscall"
// event source and we should be able to extract filter values implemented
// by both libsinsp and another plugin with field extraction capability
TEST_F(sinsp_with_test_input, plugin_syscall_source)
{
	size_t syscall_source_idx = 0;
	std::string syscall_source_name = sinsp_syscall_event_source_name;

	sinsp_filter_check_list filterlist;
	auto src_pl = register_plugin(&m_inspector, get_plugin_api_sample_syscall_source);
	auto ext_pl = register_plugin(&m_inspector, get_plugin_api_sample_syscall_extract);
	add_plugin_filterchecks(&m_inspector, ext_pl, sinsp_syscall_event_source_name, filterlist);

	// we will not use the test scap engine here, but open the src plugin instead
	// note: we configure the plugin to just emit 1 event through its open params
	m_inspector.open_plugin(src_pl->name(), "1");

	auto evt = next_event();
	ASSERT_NE(evt, nullptr);
	ASSERT_EQ(evt->get_type(), PPME_SYSCALL_OPEN_X);
	ASSERT_EQ(evt->get_source_idx(), syscall_source_idx);
	ASSERT_EQ(evt->get_tid(), (uint64_t) 1);
	ASSERT_EQ(std::string(evt->get_source_name()), syscall_source_name);
	ASSERT_EQ(get_field_as_string(evt, "fd.name", filterlist), "/tmp/the_file");
	ASSERT_EQ(get_field_as_string(evt, "fd.directory", filterlist), "/tmp");
	ASSERT_EQ(get_field_as_string(evt, "fd.filename", filterlist), "the_file");
	ASSERT_EQ(get_field_as_string(evt, "sample.is_open", filterlist), "1");
	ASSERT_FALSE(field_has_value(evt, "sample.open_count", filterlist));
	ASSERT_FALSE(field_has_value(evt, "sample.evt_count", filterlist));
	ASSERT_EQ(get_field_as_string(evt, "sample.tick", filterlist), "false");

	// We check that the plugin don't produce other events but just 1
	size_t metaevt_count = 0;
	evt = next_event(); // expecting a few or zero metaevts and then EOF
	while (evt != nullptr && metaevt_count++ < 100)
	{
		ASSERT_TRUE(libsinsp::events::is_metaevent((ppm_event_code) evt->get_type()));
		evt = next_event();
	}
}

// scenario: a plugin with field extraction capability compatible with the
// event source of another plugin should extract values from its events
TEST_F(sinsp_with_test_input, plugin_custom_source)
{
	sinsp_filter_check_list filterlist;
	auto src_pl = register_plugin(&m_inspector, get_plugin_api_sample_plugin_source);
	auto ext_pl = register_plugin(&m_inspector, get_plugin_api_sample_plugin_extract);
	add_plugin_filterchecks(&m_inspector, ext_pl, src_pl->event_source(), filterlist);

	// we will not use the test scap engine here, but open the src plugin instead
	// note: we configure the plugin to just emit 1 event through its open params
	m_inspector.open_plugin(src_pl->name(), "1");

	auto evt = next_event();
	ASSERT_NE(evt, nullptr);
	ASSERT_EQ(evt->get_type(), PPME_PLUGINEVENT_E);
	ASSERT_EQ(evt->get_source_idx(), 1);
	ASSERT_EQ(evt->get_tid(), (uint64_t) -1);
	ASSERT_EQ(std::string(evt->get_source_name()), src_pl->event_source());
	ASSERT_FALSE(field_has_value(evt, "fd.name", filterlist));
	ASSERT_EQ(get_field_as_string(evt, "evt.pluginname", filterlist), src_pl->name());
	ASSERT_EQ(get_field_as_string(evt, "sample.hello", filterlist), "hello world");
	ASSERT_EQ(next_event(), nullptr); // EOF is expected
}

TEST(sinsp_plugin, plugin_extract_compatibility)
{
	std::string tmp;
	sinsp i;
	plugin_api api;
	get_plugin_api_sample_plugin_extract(api);

	// compatible event sources specified, event types not specified
	api.get_name = [](){ return "p1"; };
	auto p = i.register_plugin(&api);
	p->init("", tmp);
	ASSERT_EQ(p->extract_event_sources().size(), 1);
	ASSERT_TRUE(sinsp_plugin::is_source_compatible(p->extract_event_sources(), "sample"));
	ASSERT_FALSE(sinsp_plugin::is_source_compatible(p->extract_event_sources(), sinsp_syscall_event_source_name));
	ASSERT_EQ(p->extract_event_codes().size(), 1);
	/* The plugin doesn't declare a list of event types and for this reason, it can extract only from pluginevent_e */
	ASSERT_TRUE(p->extract_event_codes().contains(PPME_PLUGINEVENT_E));
	ASSERT_FALSE(p->extract_event_codes().contains(PPME_SYSCALL_OPEN_E));

	// compatible event sources specified, event types specified (config-altered)
	api.get_name = [](){ return "p1-2"; };
	p = i.register_plugin(&api);
	ASSERT_ANY_THROW(p->extract_event_codes()); // can't be called before init
	p->init("322,402", tmp);
	ASSERT_EQ(p->extract_event_sources().size(), 1);
	ASSERT_TRUE(sinsp_plugin::is_source_compatible(p->extract_event_sources(), "sample"));
	ASSERT_FALSE(sinsp_plugin::is_source_compatible(p->extract_event_sources(), sinsp_syscall_event_source_name));
	ASSERT_EQ(p->extract_event_codes().size(), 2);
	ASSERT_TRUE(p->extract_event_codes().contains(PPME_PLUGINEVENT_E));
	ASSERT_TRUE(p->extract_event_codes().contains(PPME_ASYNCEVENT_E));
	ASSERT_FALSE(p->extract_event_codes().contains(PPME_SYSCALL_OPEN_E));

	// compatible event sources specified, event types specified
	api.get_name = [](){ return "p2"; };
	api.get_extract_event_types = [](uint32_t* n, ss_plugin_t* s) {
		static uint16_t ret[] = { PPME_SYSCALL_OPEN_E };
    	*n = sizeof(ret) / sizeof(uint16_t);
    	return &ret[0];
	};
	p = i.register_plugin(&api);
	p->init("", tmp);
	ASSERT_EQ(p->extract_event_sources().size(), 1);
	ASSERT_TRUE(sinsp_plugin::is_source_compatible(p->extract_event_sources(), "sample"));
	ASSERT_FALSE(sinsp_plugin::is_source_compatible(p->extract_event_sources(), sinsp_syscall_event_source_name));
	ASSERT_EQ(p->extract_event_codes().size(), 1);
	ASSERT_FALSE(p->extract_event_codes().contains(PPME_PLUGINEVENT_E));
	ASSERT_TRUE(p->extract_event_codes().contains(PPME_SYSCALL_OPEN_E));

	// compatible event sources not specified, event types not specified
	api.get_name = [](){ return "p3"; };
	api.get_extract_event_sources = NULL;
	api.get_extract_event_types = NULL;
	p = i.register_plugin(&api);
	p->init("", tmp);
	ASSERT_EQ(p->extract_event_sources().size(), 0);
	ASSERT_TRUE(sinsp_plugin::is_source_compatible(p->extract_event_sources(), "sample"));
	ASSERT_TRUE(sinsp_plugin::is_source_compatible(p->extract_event_sources(), sinsp_syscall_event_source_name));
	ASSERT_TRUE(p->extract_event_codes().contains(PPME_PLUGINEVENT_E));
	ASSERT_TRUE(p->extract_event_codes().contains(PPME_SYSCALL_OPEN_E));

	// compatible event sources not specified, event types not specified,
	// event sourcing capability is detected with specific event source
	plugin_api src_api;
	get_plugin_api_sample_plugin_source(src_api);
	api.get_name = [](){ return "p4"; };
	api.get_id = src_api.get_id;
	api.get_event_source = src_api.get_event_source;
	api.open = src_api.open;
	api.close = src_api.close;
	api.next_batch = src_api.next_batch;
	p = i.register_plugin(&api);
	p->init("", tmp);
	ASSERT_EQ(p->extract_event_sources().size(), 1);
	ASSERT_TRUE(sinsp_plugin::is_source_compatible(p->extract_event_sources(), "sample"));
	ASSERT_FALSE(sinsp_plugin::is_source_compatible(p->extract_event_sources(), sinsp_syscall_event_source_name));
	ASSERT_EQ(p->extract_event_codes().size(), 1);
	ASSERT_TRUE(p->extract_event_codes().contains(PPME_PLUGINEVENT_E));
	ASSERT_FALSE(p->extract_event_codes().contains(PPME_SYSCALL_OPEN_E));
}

// scenario: a plugin with event parsing capability and one with field
// extraction capability are loaded, both compatible with the "syscall"
// event source, and both consuming regular syscall events produced by
// any scap engine. The first is responsible of attaching an extra field to
// the sinsp thread table (a counter), and the latter extracts a field based
// on the value of the additional table's field.
TEST_F(sinsp_with_test_input, plugin_syscall_parse)
{
	// note: the "parsing" plugin will need to be loaded before the "extraction"
	// one, otherwise the latter will not be able to access the addional
	// plugin-defined field. Here we are also testing the loading order guarantees.
	register_plugin(&m_inspector, get_plugin_api_sample_syscall_parse);

	filter_check_list pl_flist;
	auto pl = register_plugin(&m_inspector, get_plugin_api_sample_syscall_extract);
	add_plugin_filterchecks(&m_inspector, pl, sinsp_syscall_event_source_name, pl_flist);
	add_default_init_thread();
	open_inspector();

	// should extract and parse regularly for non-ignored event codes
	auto evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_E, 3, "/tmp/the_file", PPM_O_RDWR, 0);
	ASSERT_EQ(get_field_as_string(evt, "sample.open_count", pl_flist), "1");
	ASSERT_EQ(get_field_as_string(evt, "sample.evt_count", pl_flist), "1");
	ASSERT_EQ(get_field_as_string(evt, "sample.tick", pl_flist), "false");

	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_X, 6, (uint64_t)3, "/tmp/the_file", PPM_O_RDWR, 0, 5, (uint64_t)123);
	ASSERT_EQ(get_field_as_string(evt, "sample.open_count", pl_flist), "2");
	ASSERT_EQ(get_field_as_string(evt, "sample.evt_count", pl_flist), "1");
	ASSERT_EQ(get_field_as_string(evt, "sample.tick", pl_flist), "false");

	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_INOTIFY_INIT1_X, 2, (int64_t)12, (uint16_t)32);
	ASSERT_EQ(get_field_as_string(evt, "sample.open_count", pl_flist), "2");
	// the parsing plugin filters-out this kind of event, so there should be no counter for it
	ASSERT_EQ(get_field_as_string(evt, "sample.evt_count", pl_flist), "0");
	ASSERT_EQ(get_field_as_string(evt, "sample.tick", pl_flist), "false");

	// should extract NULL for ignored event codes, but should still parse it (because the parsing plugin does not ignore it)
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_BY_HANDLE_AT_X, 4, 4, 5, PPM_O_RDWR, "/tmp/the_file.txt");
	ASSERT_FALSE(field_has_value(evt, "sample.open_count", pl_flist));
	ASSERT_FALSE(field_has_value(evt, "sample.evt_count", pl_flist));
	ASSERT_FALSE(field_has_value(evt, "sample.tick", pl_flist));

	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_INOTIFY_INIT1_X, 2, (int64_t)12, (uint16_t)32);
	ASSERT_EQ(get_field_as_string(evt, "sample.open_count", pl_flist), "3");
	ASSERT_EQ(get_field_as_string(evt, "sample.evt_count", pl_flist), "0");
	ASSERT_EQ(get_field_as_string(evt, "sample.tick", pl_flist), "false");

	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_X, 6, (uint64_t)4, "/tmp/the_file", PPM_O_RDWR, 0, 5, (uint64_t)123);
	ASSERT_EQ(get_field_as_string(evt, "sample.open_count", pl_flist), "4");
	// this is the second time we see this event type
	ASSERT_EQ(get_field_as_string(evt, "sample.evt_count", pl_flist), "2");
	ASSERT_EQ(get_field_as_string(evt, "sample.tick", pl_flist), "false");
}

// scenario: a plugin with async events capability and one with field
// extraction capability are loaded, both compatible with the "syscall"
// event source. An inspector is opened in no driver mode, so that
// the only events received are the ones coming from the async plugin.
// note: emscripten has trouble with the nodriver engine and async events
#if !defined(__EMSCRIPTEN__)
TEST_F(sinsp_with_test_input, plugin_syscall_async)
{
	uint64_t max_count = 10;
	uint64_t period_ns = 1000000; // 1ms
	/* async plugin config */
	std::string async_pl_cfg = std::to_string(max_count) + ":" + std::to_string(period_ns);
	std::string srcname = sinsp_syscall_event_source_name;

	sinsp_filter_check_list filterlist;
	register_plugin(&m_inspector, get_plugin_api_sample_syscall_async, async_pl_cfg);
	auto ext_pl = register_plugin(&m_inspector, get_plugin_api_sample_syscall_extract);
	add_plugin_filterchecks(&m_inspector, ext_pl, srcname, filterlist);

	// check that the async event name is an accepted evt.type value
	std::unique_ptr<sinsp_filter_check> chk(filterlist.new_filter_check_from_fldname("evt.type", &m_inspector, false));
	ASSERT_GT(chk->parse_field_name("evt.type", true, false), 0);
	ASSERT_NO_THROW(chk->add_filter_value("openat", strlen("openat") + 1, 0));
	ASSERT_NO_THROW(chk->add_filter_value("sampleticker", strlen("sampleticker") + 1, 1));
	ASSERT_ANY_THROW(chk->add_filter_value("badname", strlen("badname") + 1, 2));

	// we will not use the test scap engine here, but open the no-driver instead
	uint64_t count = 0;
	uint64_t cycles = 0;
	uint64_t max_cycles = max_count * 8; // avoid infinite loops
	sinsp_evt *evt = NULL;
	int32_t rc = SCAP_SUCCESS;
	uint64_t last_ts = 0;
	m_inspector.open_nodriver();
	while (rc == SCAP_SUCCESS && cycles < max_cycles && count < max_count)
	{
		cycles++;
		rc = m_inspector.next(&evt);
		/* The no driver engine sends only `PPME_SCAPEVENT_X` events */
		if (rc == SCAP_TIMEOUT || evt->get_type() == PPME_SCAPEVENT_X)
		{
			// wait a bit so that the plugin can fire the async event
			std::this_thread::sleep_for(std::chrono::nanoseconds(period_ns));
			rc = SCAP_SUCCESS;
			continue;
		}
		count++;
		ASSERT_NE(evt, nullptr);
		ASSERT_EQ(evt->get_type(), PPME_ASYNCEVENT_E);
		ASSERT_EQ(evt->get_tid(), 1);
		ASSERT_EQ(evt->get_source_idx(), 0); // "syscall" source
		ASSERT_EQ(std::string(evt->get_source_name()), srcname);
		if (cycles > 1)
		{
			ASSERT_GE(evt->get_ts(), last_ts);
		}
		ASSERT_FALSE(field_has_value(evt, "evt.pluginname", filterlist)); // not available for "syscall" async events
		ASSERT_FALSE(field_has_value(evt, "evt.plugininfo", filterlist));
		ASSERT_EQ(get_field_as_string(evt, "evt.is_async", filterlist), "true");
		ASSERT_EQ(get_field_as_string(evt, "evt.asynctype", filterlist), "sampleticker");
		ASSERT_EQ(get_field_as_string(evt, "evt.type", filterlist), "sampleticker");
		ASSERT_EQ(get_field_as_string(evt, "sample.tick", filterlist), "true");
		last_ts = evt->get_ts();
	}
	m_inspector.close();
	ASSERT_EQ(count, max_count);
}
#endif // !defined(__EMSCRIPTEN__)

// Scenario we load a plugin that parses any event and plays with the
// thread table, by stressing all the operations supported. After that, we
// also play with the plugin's table from the inspector C++ interface.
// Basically, we are verifying that the sinsp <-> plugin tables access
// is bidirectional and consistent.
TEST_F(sinsp_with_test_input, plugin_tables)
{
	auto& reg = m_inspector.get_table_registry();

	add_default_init_thread();

	// the threads table is always present
	ASSERT_EQ(reg->tables().size(), 1);
	ASSERT_NE(reg->tables().find("threads"), reg->tables().end());

	// make sure we see a new table when we register the plugin
	ASSERT_EQ(reg->tables().find("plugin_sample"), reg->tables().end());
	ASSERT_EQ(reg->get_table<uint64_t>("plugin_sample"), nullptr);
	register_plugin(&m_inspector, get_plugin_api_sample_tables);
	ASSERT_EQ(reg->tables().size(), 2);
	ASSERT_NE(reg->tables().find("plugin_sample"), reg->tables().end());
	ASSERT_ANY_THROW(reg->get_table<char>("plugin_sample")); // wrong key type
	ASSERT_NE(reg->get_table<uint64_t>("plugin_sample"), nullptr);

	// get the plugin table and check its fields and info
	auto table = reg->get_table<uint64_t>("plugin_sample");
	ASSERT_EQ(table->name(), "plugin_sample");
	ASSERT_EQ(table->entries_count(), 0);
	ASSERT_EQ(table->key_info(), libsinsp::state::typeinfo::of<uint64_t>());
	ASSERT_EQ(table->static_fields().size(), 0);
	ASSERT_EQ(table->dynamic_fields()->fields().size(), 1);

	// get an already existing field form the plugin table
	auto sfield = table->dynamic_fields()->fields().find("u64_val");
	ASSERT_NE(sfield, table->dynamic_fields()->fields().end());
	ASSERT_EQ(sfield->second.readonly(), false);
	ASSERT_EQ(sfield->second.valid(), true);
	ASSERT_EQ(sfield->second.index(), 0);
	ASSERT_EQ(sfield->second.name(), "u64_val");
	ASSERT_EQ(sfield->second.info(), libsinsp::state::typeinfo::of<uint64_t>());

	// add a new field in the plugin table
	const auto& dfield = table->dynamic_fields()->add_field<std::string>("str_val");
	ASSERT_NE(table->dynamic_fields()->fields().find("str_val"), table->dynamic_fields()->fields().end());
	ASSERT_EQ(dfield, table->dynamic_fields()->fields().find("str_val")->second);
	ASSERT_EQ(dfield.readonly(), false);
	ASSERT_EQ(dfield.valid(), true);
	ASSERT_EQ(dfield.index(), 1);
	ASSERT_EQ(dfield.name(), "str_val");
	ASSERT_EQ(dfield.info(), libsinsp::state::typeinfo::of<std::string>());

	// we open a capture and iterate, so that we make sure that all
	// the state operations keep working at every round of the loop
	open_inspector();
	auto asyncname = "sampleasync";
	auto sample_plugin_evtdata = "hello world";
	uint64_t max_iterations = 10000;
	for (uint64_t i = 0; i < max_iterations; i++)
	{
		auto evt = add_event_advance_ts(increasing_ts(), 1, PPME_ASYNCEVENT_E, 3, (uint32_t) 0, asyncname, scap_const_sized_buffer{&sample_plugin_evtdata, strlen(sample_plugin_evtdata) + 1});
		ASSERT_EQ(evt->get_type(), PPME_ASYNCEVENT_E);
		ASSERT_EQ(evt->get_source_idx(), 0);
	}

	// we play around with the plugin's table, like if it was a C++ one from sinsp
	auto sfieldacc = sfield->second.new_accessor<uint64_t>();
	auto dfieldacc = dfield.new_accessor<std::string>();

	for (uint64_t i = 0; i < max_iterations; i++)
	{
		ASSERT_EQ(table->entries_count(), i);

		// get non-existing entry
		ASSERT_EQ(table->get_entry(i), nullptr);

		// creating a destroying a thread without adding it to the table
		table->new_entry();

		// creating and adding a thread to the table
		auto t = table->add_entry(i, table->new_entry());
		ASSERT_NE(t, nullptr);
		ASSERT_NE(table->get_entry(i), nullptr);
		ASSERT_EQ(table->entries_count(), i + 1);

		// read and write from newly-created thread (existing field)
		uint64_t tmpu64 = (uint64_t) -1;
		t->get_dynamic_field(sfieldacc, tmpu64);
		ASSERT_EQ(tmpu64, 0);
		tmpu64 = 5;
		t->set_dynamic_field(sfieldacc, tmpu64);
		tmpu64 = 0;
		t->get_dynamic_field(sfieldacc, tmpu64);
		ASSERT_EQ(tmpu64, 5);

		// read and write from newly-created thread (added field)
		std::string tmpstr = "test";
		t->get_dynamic_field(dfieldacc, tmpstr);
		ASSERT_EQ(tmpstr, "");
		tmpstr = "hello";
		t->set_dynamic_field(dfieldacc, tmpstr);
		tmpstr = "";
		t->get_dynamic_field(dfieldacc, tmpstr);
		ASSERT_EQ(tmpstr, "hello");
	}

	// full iteration
	auto it = [&](libsinsp::state::table_entry& e) -> bool
	{
		uint64_t tmpu64;
		std::string tmpstr;
		e.get_dynamic_field(sfieldacc, tmpu64);
		EXPECT_EQ(tmpu64, 5);
		e.get_dynamic_field(dfieldacc, tmpstr);
		EXPECT_EQ(tmpstr, "hello");
		return true;
	};
	ASSERT_TRUE(table->foreach_entry(it));

	// iteration with break-out
	ASSERT_FALSE(table->foreach_entry([&](libsinsp::state::table_entry& e) -> bool
	{
		return false;
	}));

	// iteration with error
	ASSERT_ANY_THROW(table->foreach_entry([&](libsinsp::state::table_entry& e) -> bool
	{
		throw sinsp_exception("some error");
	}));

	// erasing an unknown thread
	ASSERT_EQ(table->erase_entry(max_iterations), false);
	ASSERT_EQ(table->entries_count(), max_iterations);

	// erase one of the newly-created thread
	ASSERT_EQ(table->erase_entry(0), true);
	ASSERT_EQ(table->entries_count(), max_iterations - 1);

	// clear all
	ASSERT_NO_THROW(table->clear_entries());
	ASSERT_EQ(table->entries_count(), 0);
}

// Scenario: we load a plugin expecting it to log
// when it's initialized and destroyed.
// We use a callback attached to the logger to assert the message.
// When the inspector goes out of scope,
// the plugin is automatically destroyed.
TEST(sinsp_plugin, plugin_logging)
{
	{
		std::string tmp;
		sinsp i;
		plugin_api api;
		get_plugin_api_sample_plugin_extract(api);

		libsinsp_logger()->add_callback_log([](std::string&& str, sinsp_logger::severity sev) {
			std::string expected = "some component: initializing plugin..."; 
			ASSERT_TRUE(std::equal(expected.rbegin(), expected.rend(), str.rbegin()));
		});

		api.get_name = [](){ return "p1"; };
		auto p = i.register_plugin(&api);
		p->init("", tmp);

		libsinsp_logger()->add_callback_log([](std::string&& str, sinsp_logger::severity sev) {
			std::string expected = "some component: destroying plugin..."; 
			ASSERT_TRUE(std::equal(expected.rbegin(), expected.rend(), str.rbegin()));
		});
	}

	libsinsp_logger()->remove_callback_log();
}

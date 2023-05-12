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
#include <plugin.h>

#include "sinsp_with_test_input.h"
#include "test_utils.h"
#include "plugins/test_plugins.h"

static std::shared_ptr<sinsp_plugin> register_plugin(
		sinsp* i,
		std::function<void(plugin_api&)> constructor,
		const std::string& initcfg = "")
{
	std::string err;
	plugin_api api;
	constructor(api);
	auto pl = i->register_plugin(&api);
	if (!pl->init(initcfg, err))
	{
		throw sinsp_exception(err);
	}
	return pl;
}

static void add_plugin_filterchecks(
		sinsp* i,
		std::shared_ptr<sinsp_plugin> p,
		const std::string& src,
		filter_check_list& fl = g_filterlist)
{
	if (p->caps() & CAP_EXTRACTION
		&& sinsp_plugin::is_source_compatible(p->extract_event_sources(), src))
	{
		fl.add_filter_check(i->new_generic_filtercheck());
		fl.add_filter_check(sinsp_plugin::new_filtercheck(p));
	}
}

// scenario: a plugin with field extraction capability compatible with the
// "syscall" event source should be able to extract filter values from
// regular syscall events produced by any scap engine.
TEST_F(sinsp_with_test_input, plugin_syscall_extract)
{
	size_t syscall_source_idx = 0;
	std::string syscall_source_name = sinsp_syscall_event_source_name;

	filter_check_list pl_flist;
	register_plugin(&m_inspector, get_plugin_api_sample_plugin_source);
	auto pl = register_plugin(&m_inspector, get_plugin_api_sample_syscall_extract);
	add_plugin_filterchecks(&m_inspector, pl, sinsp_syscall_event_source_name, pl_flist);
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
	ASSERT_FALSE(field_exists(evt, "sample.open_count", pl_flist));
	ASSERT_FALSE(field_exists(evt, "sample.evt_count", pl_flist));
	ASSERT_EQ(get_field_as_string(evt, "sample.tick", pl_flist), "false");

	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_INOTIFY_INIT1_X, 2, (int64_t)12, (uint16_t)32);
	ASSERT_EQ(evt->get_source_idx(), syscall_source_idx);
	ASSERT_EQ(std::string(evt->get_source_name()), syscall_source_name);
	ASSERT_EQ(evt->get_type(), PPME_SYSCALL_INOTIFY_INIT1_X);
	ASSERT_EQ(get_field_as_string(evt, "sample.is_open", pl_flist), "0");
	ASSERT_EQ(get_field_as_string(evt, "sample.proc_name", pl_flist), "init");
	ASSERT_FALSE(field_exists(evt, "sample.open_count", pl_flist));
	ASSERT_FALSE(field_exists(evt, "sample.evt_count", pl_flist));
	ASSERT_EQ(get_field_as_string(evt, "sample.tick", pl_flist), "false");

	// should extract NULL for ignored event codes
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_BY_HANDLE_AT_X, 4, 4, 5, PPM_O_RDWR, "/tmp/the_file.txt");
	ASSERT_EQ(evt->get_source_idx(), syscall_source_idx);
	ASSERT_EQ(std::string(evt->get_source_name()), syscall_source_name);
	ASSERT_EQ(evt->get_type(), PPME_SYSCALL_OPEN_BY_HANDLE_AT_X);
	ASSERT_FALSE(field_exists(evt, "sample.is_open", pl_flist));
	ASSERT_FALSE(field_exists(evt, "sample.proc_name", pl_flist));
	ASSERT_FALSE(field_exists(evt, "sample.open_count", pl_flist));
	ASSERT_FALSE(field_exists(evt, "sample.evt_count", pl_flist));
	ASSERT_FALSE(field_exists(evt, "sample.tick", pl_flist));

	// should extract NULL for unknown event sources
	const char data[2048] = "hello world";
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_PLUGINEVENT_E, 2, (uint64_t) 1, scap_const_sized_buffer{&data, strlen(data) + 1});
	ASSERT_EQ(evt->get_source_idx(), sinsp_no_event_source_idx);
	ASSERT_EQ(evt->get_source_name(), sinsp_no_event_source_name);
	ASSERT_EQ(evt->get_type(), PPME_PLUGINEVENT_E);
	ASSERT_FALSE(field_exists(evt, "sample.is_open", pl_flist));
	ASSERT_FALSE(field_exists(evt, "sample.proc_name", pl_flist));
	ASSERT_FALSE(field_exists(evt, "sample.open_count", pl_flist));
	ASSERT_FALSE(field_exists(evt, "sample.evt_count", pl_flist));
	ASSERT_FALSE(field_exists(evt, "sample.tick", pl_flist));

	// should extract NULL for non-compatible event sources
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_PLUGINEVENT_E, 2, (uint64_t) 999, scap_const_sized_buffer{&data, strlen(data) + 1});
	ASSERT_EQ(evt->get_source_idx(), 1);
	ASSERT_EQ(std::string(evt->get_source_name()), std::string("sample"));
	ASSERT_EQ(evt->get_type(), PPME_PLUGINEVENT_E);
	ASSERT_FALSE(field_exists(evt, "sample.is_open", pl_flist));
	ASSERT_FALSE(field_exists(evt, "sample.proc_name", pl_flist));
	ASSERT_FALSE(field_exists(evt, "sample.open_count", pl_flist));
	ASSERT_FALSE(field_exists(evt, "sample.evt_count", pl_flist));
	ASSERT_FALSE(field_exists(evt, "sample.tick", pl_flist));
}

// scenario: an event sourcing plugin should produce events of "syscall"
// event source and we're should be able to extract filter values implemented
// by both libsinsp and another plugin with field extraction capability
TEST_F(sinsp_with_test_input, plugin_syscall_source)
{
	size_t syscall_source_idx = 0;
	std::string syscall_source_name = sinsp_syscall_event_source_name;

	auto src_pl = register_plugin(&m_inspector, get_plugin_api_sample_syscall_source);
	auto ext_pl = register_plugin(&m_inspector, get_plugin_api_sample_syscall_extract);
	add_plugin_filterchecks(&m_inspector, ext_pl, sinsp_syscall_event_source_name);

	// we will not use the test scap engine here, but open the src plugin instead
	// note: we configure the plugin to just emit 1 event through its open params
	m_inspector.open_plugin(src_pl->name(), "1");

	auto evt = next_event();
	ASSERT_NE(evt, nullptr);
	ASSERT_EQ(evt->get_type(), PPME_SYSCALL_OPEN_X);
	ASSERT_EQ(evt->get_source_idx(), syscall_source_idx);
	ASSERT_EQ(std::string(evt->get_source_name()), syscall_source_name);
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), "/tmp/the_file");
	ASSERT_EQ(get_field_as_string(evt, "fd.directory"), "/tmp");
	ASSERT_EQ(get_field_as_string(evt, "fd.filename"), "the_file");
	ASSERT_EQ(get_field_as_string(evt, "sample.is_open"), "1");
	ASSERT_FALSE(field_exists(evt, "sample.open_count"));
	ASSERT_FALSE(field_exists(evt, "sample.evt_count"));
	ASSERT_EQ(get_field_as_string(evt, "sample.tick"), "false");
	ASSERT_EQ(next_event(), nullptr); // EOF is expected
}

// scenario: a plugin with field extraction capability compatible with the
// event source of another plugin should extract values from its events
TEST_F(sinsp_with_test_input, plugin_custom_source)
{
	auto src_pl = register_plugin(&m_inspector, get_plugin_api_sample_plugin_source);
	auto ext_pl = register_plugin(&m_inspector, get_plugin_api_sample_plugin_extract);
	add_plugin_filterchecks(&m_inspector, ext_pl, src_pl->event_source());

	// we will not use the test scap engine here, but open the src plugin instead
	// note: we configure the plugin to just emit 1 event through its open params
	m_inspector.open_plugin(src_pl->name(), "1");

	auto evt = next_event();
	ASSERT_NE(evt, nullptr);
	ASSERT_EQ(evt->get_type(), PPME_PLUGINEVENT_E);
	ASSERT_EQ(evt->get_source_idx(), 1);
	ASSERT_EQ(std::string(evt->get_source_name()), src_pl->event_source());
	ASSERT_FALSE(field_exists(evt, "fd.name"));
	ASSERT_EQ(get_field_as_string(evt, "evt.pluginname"), src_pl->name());
	ASSERT_EQ(get_field_as_string(evt, "sample.hello"), "hello world");
	ASSERT_EQ(next_event(), nullptr); // EOF is expected
}

TEST(sinsp_plugin, plugin_extract_compatibility)
{
	sinsp i;
	plugin_api api;
	get_plugin_api_sample_plugin_extract(api);

	// compatible event sources specified, event types not specified
	api.get_name = [](){ return "p1"; };
	auto p = i.register_plugin(&api);
	ASSERT_EQ(p->extract_event_sources().size(), 1);
	ASSERT_TRUE(sinsp_plugin::is_source_compatible(p->extract_event_sources(), "sample"));
	ASSERT_FALSE(sinsp_plugin::is_source_compatible(p->extract_event_sources(), sinsp_syscall_event_source_name));
	ASSERT_EQ(p->extract_event_codes().size(), 1);
	ASSERT_TRUE(p->extract_event_codes().contains(PPME_PLUGINEVENT_E));
	ASSERT_FALSE(p->extract_event_codes().contains(PPME_SYSCALL_OPEN_E));

	// compatible event sources specified, event types specified
	api.get_name = [](){ return "p2"; };
	api.get_extract_event_types = [](uint32_t* n) {
		static uint16_t ret[] = { PPME_SYSCALL_OPEN_E };
    	*n = sizeof(ret) / sizeof(uint16_t);
    	return &ret[0];
	};
	p = i.register_plugin(&api);
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
	ASSERT_FALSE(field_exists(evt, "sample.open_count", pl_flist));
	ASSERT_FALSE(field_exists(evt, "sample.evt_count", pl_flist));
	ASSERT_FALSE(field_exists(evt, "sample.tick", pl_flist));

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
TEST_F(sinsp_with_test_input, plugin_syscall_async)
{
	uint64_t max_count = 10;
	uint64_t period_ns = 1000000; // 1ms
	std::string async_pl_cfg = std::to_string(max_count) + ":" + std::to_string(period_ns);
	std::string srcname = sinsp_syscall_event_source_name;

	register_plugin(&m_inspector, get_plugin_api_sample_syscall_async, async_pl_cfg);
	auto ext_pl = register_plugin(&m_inspector, get_plugin_api_sample_syscall_extract);
	add_plugin_filterchecks(&m_inspector, ext_pl, srcname);

	// check that the async event name is an accepted evt.type value
	std::unique_ptr<sinsp_filter_check> chk(g_filterlist.new_filter_check_from_fldname("evt.type", &m_inspector, false));
	ASSERT_GT(chk->parse_field_name("evt.type", true, false), 0);
	ASSERT_NO_THROW(chk->add_filter_value("openat", strlen("openat") + 1, 0));
	ASSERT_NO_THROW(chk->add_filter_value("sampleticker", strlen("sampleticker") + 1, 1));
	ASSERT_ANY_THROW(chk->add_filter_value("badname", strlen("badname") + 1, 2));

	// we will not use the test scap engine here, but open the src plugin instead
	// note: we configure the plugin to just emit 1 event through its open params
	uint64_t count = 0;
	uint64_t cycles = 0;
	uint64_t max_cycles = max_count * 1.5; // avoid infinite loops
	sinsp_evt *evt = NULL;
	int32_t rc = SCAP_SUCCESS;
	uint64_t last_ts = 0;
	m_inspector.open_nodriver();
	while (rc == SCAP_SUCCESS && cycles < max_cycles && count < max_count)
	{
		cycles++;
		rc = m_inspector.next(&evt);
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
		ASSERT_EQ(evt->get_source_idx(), 0); // "syscall" source
		ASSERT_EQ(std::string(evt->get_source_name()), srcname);
		if (cycles > 1)
		{
			ASSERT_GE(evt->get_ts(), last_ts);
		}
		ASSERT_FALSE(field_exists(evt, "evt.pluginname")); // not available for "syscall" async events
		ASSERT_FALSE(field_exists(evt, "evt.plugininfo"));
		ASSERT_EQ(get_field_as_string(evt, "evt.is_async"), "true");
		ASSERT_EQ(get_field_as_string(evt, "evt.asynctype"), "sampleticker");
		ASSERT_EQ(get_field_as_string(evt, "evt.type"), "sampleticker");
		ASSERT_EQ(get_field_as_string(evt, "sample.tick"), "true");
		last_ts = evt->get_ts();
	}
	m_inspector.close();
	ASSERT_EQ(count, max_count);
}

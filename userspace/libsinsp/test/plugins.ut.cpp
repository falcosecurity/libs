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

#include <thread>
#include <functional>
#include <sstream>
#include <gtest/gtest.h>
#include <libsinsp/plugin.h>
#include <libsinsp/test/helpers/threads_helpers.h>

#include <sinsp_with_test_input.h>
#include "test_utils.h"
#include "plugins/test_plugins.h"

static std::shared_ptr<sinsp_plugin> register_plugin_api(sinsp* i,
                                                         plugin_api& api,
                                                         const std::string& initcfg = "") {
	std::string err;
	auto pl = i->register_plugin(&api);
	if(!pl->init(initcfg, err)) {
		throw sinsp_exception(err);
	}
	return pl;
}

static std::shared_ptr<sinsp_plugin> register_plugin(sinsp* i,
                                                     std::function<void(plugin_api&)> constructor,
                                                     const std::string& initcfg = "") {
	plugin_api api;
	constructor(api);
	return register_plugin_api(i, api, initcfg);
}

static void add_plugin_filterchecks(sinsp* i,
                                    std::shared_ptr<sinsp_plugin> p,
                                    const std::string& src,
                                    filter_check_list& fl) {
	if(p->caps() & CAP_EXTRACTION &&
	   sinsp_plugin::is_source_compatible(p->extract_event_sources(), src)) {
		fl.add_filter_check(i->new_generic_filtercheck());
		fl.add_filter_check(sinsp_plugin::new_filtercheck(p));
	}
}

TEST(plugins, broken_source_capability) {
	plugin_api api;

	{
		get_plugin_api_sample_plugin_source(api);
		sinsp inspector;

		// The example plugin has id 999 so `!= 0`. For this reason,
		// the event source name should be different from "syscall"
		api.get_id = []() { return (uint32_t)999; };
		api.get_event_source = []() { return sinsp_syscall_event_source_name; };
		ASSERT_ANY_THROW(register_plugin_api(&inspector, api));

		// `get_event_source` is implemented so also `get_id` should be implemented
		api.get_id = NULL;
		api.get_event_source = []() { return sinsp_syscall_event_source_name; };
		ASSERT_ANY_THROW(register_plugin_api(&inspector, api));

		// Now both methods are NULL so we are ok!
		api.get_id = NULL;
		api.get_event_source = NULL;
		ASSERT_NO_THROW(register_plugin_api(&inspector, api));
	}

	// restore inspector and source API
	{
		get_plugin_api_sample_plugin_source(api);
		sinsp inspector;

		// `open`, `close`, `next_batch` must be all defined to provide source capability
		api.open = NULL;
		ASSERT_ANY_THROW(register_plugin_api(&inspector, api));
		api.close = NULL;
		ASSERT_ANY_THROW(register_plugin_api(&inspector, api));
		api.next_batch = NULL;

		// Now that all the 3 methods are NULL the plugin has no more capabilities
		// so we should throw an exception because every plugin should implement at least one
		// capability
		ASSERT_ANY_THROW(register_plugin_api(&inspector, api));
	}
}

TEST(plugins, broken_extract_capability) {
	plugin_api api;
	get_plugin_api_sample_plugin_extract(api);
	sinsp inspector;

	api.get_fields = []() { return "[]"; };
	ASSERT_THROW(register_plugin_api(&inspector, api), sinsp_exception);

	// `extract_fields` is defined but `get_fields` no
	api.get_fields = NULL;
	ASSERT_ANY_THROW(register_plugin_api(&inspector, api));

	// Both NULL, the plugin has no capabilities
	api.get_fields = NULL;
	api.extract_fields = NULL;
	ASSERT_ANY_THROW(register_plugin_api(&inspector, api));
}

TEST(plugins, broken_parsing_capability) {
	plugin_api api;
	get_plugin_api_sample_syscall_parse(api);
	sinsp inspector;

	// The plugin has no capabilities
	api.parse_event = NULL;
	ASSERT_ANY_THROW(register_plugin_api(&inspector, api));
}

TEST(plugins, broken_async_capability) {
	plugin_api api;
	get_plugin_api_sample_syscall_async(api);
	sinsp inspector;

	/* `set_async_event_handler` is defined but `get_async_events` is not */
	api.get_async_events = NULL;
	ASSERT_ANY_THROW(register_plugin_api(&inspector, api));

	// Both NULL, the plugin has no capabilities
	api.get_async_events = NULL;
	api.set_async_event_handler = NULL;
	ASSERT_ANY_THROW(register_plugin_api(&inspector, api));
}

// scenario: a plugin with field extraction capability compatible with the
// "syscall" event source should be able to extract filter values from
// regular syscall events produced by any scap engine.
TEST_F(sinsp_with_test_input, plugin_syscall_extract) {
	size_t syscall_source_idx = 0;
	std::string syscall_source_name = sinsp_syscall_event_source_name;

	filter_check_list pl_flist;

	// Register a plugin with source capabilities
	register_plugin(&m_inspector, get_plugin_api_sample_plugin_source);

	// Register a plugin with extraction capabilities
	auto pl = register_plugin(&m_inspector, get_plugin_api_sample_syscall_extract);

	// This plugin tells that it can receive `syscall` events
	add_plugin_filterchecks(&m_inspector, pl, sinsp_syscall_event_source_name, pl_flist);

	// Since `%sample.is_open` field was requested by the plugin as an addOutput field,
	// its filtercheck shall have the EPF_FORMAT_SUGGESTED flag.
	std::vector<const filter_check_info*> fields;
	pl_flist.get_all_fields(fields);
	for(const auto& field : fields) {
		if(field->m_name == "sample.is_open") {
			ASSERT_TRUE(field->m_flags & EPF_FORMAT_SUGGESTED);
		}
	}

	// Open the inspector in test mode
	add_default_init_thread();
	open_inspector();

	// should extract legit values for non-ignored event codes
	auto evt = add_event_advance_ts(increasing_ts(),
	                                1,
	                                PPME_SYSCALL_OPEN_X,
	                                6,
	                                (uint64_t)3,
	                                "/tmp/the_file",
	                                PPM_O_RDWR,
	                                0,
	                                5,
	                                (uint64_t)123);
	ASSERT_EQ(evt->get_source_idx(), syscall_source_idx);
	ASSERT_EQ(std::string(evt->get_source_name()), syscall_source_name);
	ASSERT_EQ(evt->get_type(), PPME_SYSCALL_OPEN_X);
	ASSERT_EQ(get_field_as_string(evt, "sample.is_open", pl_flist), "1");
	ASSERT_EQ(get_field_as_string(evt, "sample.proc_name", pl_flist), "init");
	ASSERT_FALSE(field_has_value(evt, "sample.open_count", pl_flist));
	ASSERT_FALSE(field_has_value(evt, "sample.evt_count", pl_flist));
	ASSERT_EQ(get_field_as_string(evt, "sample.tick", pl_flist), "false");

	// Check rhs filter checks support on plugins

	// Check on strings
	ASSERT_EQ(get_field_as_string(evt, "sample.proc_name", pl_flist), "init");
	ASSERT_TRUE(eval_filter(evt, "(sample.proc_name = init)", pl_flist));
	ASSERT_FALSE(eval_filter(evt, "(sample.proc_name = sample.proc_name)", pl_flist));
	ASSERT_TRUE(eval_filter(evt, "(sample.proc_name = val(sample.proc_name))", pl_flist));
	ASSERT_FALSE(eval_filter(evt, "(sample.proc_name = val(sample.tick))", pl_flist));
	ASSERT_FALSE(eval_filter(evt, "(sample.proc_name = val(evt.pluginname))", pl_flist));
	ASSERT_FALSE(eval_filter(evt, "(evt.pluginname = val(sample.proc_name))", pl_flist));

	// Check on uin64_t
	ASSERT_TRUE(eval_filter(evt, "(sample.is_open = 1)", pl_flist));
	ASSERT_FALSE(filter_compiles("(sample.is_open = sample.is_open)", pl_flist));
	ASSERT_TRUE(eval_filter(evt, "(sample.is_open = val(sample.is_open))", pl_flist));

	// Check transformers on plugins filter checks
	ASSERT_FALSE(eval_filter(evt, "(toupper(sample.proc_name) = init)", pl_flist));
	ASSERT_TRUE(eval_filter(evt, "(toupper(sample.proc_name) = INIT)", pl_flist));
	ASSERT_TRUE(eval_filter(evt, "(tolower(toupper(sample.proc_name)) = init)", pl_flist));
	ASSERT_TRUE(
	        eval_filter(evt,
	                    "(tolower(toupper(sample.proc_name)) = tolower(toupper(sample.proc_name)))",
	                    pl_flist));
	ASSERT_TRUE(
	        eval_filter(evt, "(toupper(sample.proc_name) = toupper(sample.proc_name))", pl_flist));

	// Here `sample.is_open` should be false
	evt = add_event_advance_ts(increasing_ts(),
	                           1,
	                           PPME_SYSCALL_INOTIFY_INIT1_X,
	                           2,
	                           (int64_t)12,
	                           (uint16_t)32);
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
	evt = add_event_advance_ts(increasing_ts(),
	                           1,
	                           PPME_SYSCALL_OPEN_BY_HANDLE_AT_X,
	                           4,
	                           (uint64_t)4,
	                           (uint64_t)5,
	                           PPM_O_RDWR,
	                           "/tmp/the_file.txt");
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
	uint32_t unknwon_plugin_id = 1;
	evt = add_event_advance_ts(increasing_ts(),
	                           1,
	                           PPME_PLUGINEVENT_E,
	                           2,
	                           unknwon_plugin_id,
	                           scap_const_sized_buffer{&data, strlen(data) + 1});
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
	uint32_t source_plugin_id = 999;
	evt = add_event_advance_ts(increasing_ts(),
	                           1,
	                           PPME_PLUGINEVENT_E,
	                           2,
	                           source_plugin_id,
	                           scap_const_sized_buffer{&data, strlen(data) + 1});
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
TEST_F(sinsp_with_test_input, plugin_syscall_source) {
	size_t syscall_source_idx = 0;
	std::string syscall_source_name = sinsp_syscall_event_source_name;

	sinsp_filter_check_list filterlist;
	auto src_pl = register_plugin(&m_inspector, get_plugin_api_sample_syscall_source);
	auto ext_pl = register_plugin(&m_inspector, get_plugin_api_sample_syscall_extract);
	add_plugin_filterchecks(&m_inspector, ext_pl, sinsp_syscall_event_source_name, filterlist);

	// we will not use the test scap engine here, but open the src plugin instead
	// note: we configure the plugin to just emit 1 event through its open params
	m_inspector.open_plugin(src_pl->name(), "1", sinsp_plugin_platform::SINSP_PLATFORM_HOSTINFO);

#ifdef __linux__
	// The LINUX_HOSTINFO platform type fills in machine_info, but only on Linux
	// (non-Linux platforms have a stub implementation in scap.c)
	ASSERT_GT(m_inspector.get_machine_info()->num_cpus, 0);
#endif

	auto evt = next_event();
	ASSERT_NE(evt, nullptr);
	ASSERT_EQ(evt->get_type(), PPME_SYSCALL_OPEN_X);
	ASSERT_EQ(evt->get_source_idx(), syscall_source_idx);
	ASSERT_EQ(evt->get_tid(), (uint64_t)1);
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
	evt = next_event();  // expecting a few or zero metaevts and then EOF
	while(evt != nullptr && metaevt_count++ < 100) {
		ASSERT_TRUE(libsinsp::events::is_metaevent((ppm_event_code)evt->get_type()));
		evt = next_event();
	}
}

// scenario: a plugin with field extraction capability compatible with the
// event source of another plugin should extract values from its events
TEST_F(sinsp_with_test_input, plugin_custom_source) {
	sinsp_filter_check_list filterlist;
	auto src_pl = register_plugin(&m_inspector, get_plugin_api_sample_plugin_source);
	auto ext_pl = register_plugin(&m_inspector, get_plugin_api_sample_plugin_extract);
	add_plugin_filterchecks(&m_inspector, ext_pl, src_pl->event_source(), filterlist);

	// we will not use the test scap engine here, but open the src plugin instead
	// note: we configure the plugin to just emit 1 event through its open params
	m_inspector.open_plugin(src_pl->name(), "1", sinsp_plugin_platform::SINSP_PLATFORM_GENERIC);

	// the GENERIC platform type does not fill in machine_info
	ASSERT_EQ(m_inspector.get_machine_info()->num_cpus, 0);

	// Since `%sample.hello` field was requested by the plugin as an addOutput field,
	// its value should be present in the output.
	std::vector<const filter_check_info*> fields;
	filterlist.get_all_fields(fields);
	for(const auto& field : fields) {
		if(field->m_name == "sample.hello") {
			ASSERT_TRUE(field->m_flags & EPF_FORMAT_SUGGESTED);
		}
	}

	auto evt = next_event();
	ASSERT_NE(evt, nullptr);
	ASSERT_EQ(evt->get_type(), PPME_PLUGINEVENT_E);
	ASSERT_EQ(evt->get_source_idx(), 1);
	ASSERT_EQ(evt->get_tid(), (uint64_t)-1);
	ASSERT_EQ(std::string(evt->get_source_name()), src_pl->event_source());
	ASSERT_FALSE(field_has_value(evt, "fd.name", filterlist));
	ASSERT_EQ(get_field_as_string(evt, "evt.pluginname", filterlist), src_pl->name());
	ASSERT_EQ(get_field_as_string(evt, "sample.hello", filterlist), "hello world");

	auto offset = get_value_offset_start(evt, "sample.hello", filterlist, 0);
	ASSERT_EQ(offset, PLUGIN_EVENT_PAYLOAD_OFFSET);
	auto length = get_value_offset_length(evt, "sample.hello", filterlist, 0);
	ASSERT_EQ(length, 11);

	const auto raw_evt = reinterpret_cast<const char*>(evt->get_scap_evt());
	for(uint32_t i = 0; i < evt->get_scap_evt()->len; i++) {
		printf("%02x ", static_cast<unsigned char>(raw_evt[i]));
	}
	printf("\n");
	for(uint32_t i = 0; i < evt->get_scap_evt()->len; i++) {
		char c = ' ';
		if(i >= offset && i < offset + length) {
			c = '^';
		}
		printf("%c%c%c", c, c, c);
	}
	printf("\n");

	// Note: here we are asserting that the exact bytes are present in the event payload
	// This does not need to hold for all plugins (e.g. due to serialization format)
	// but is a useful check here to validate we got the offsets correct.
	ASSERT_EQ(memcmp(raw_evt + offset, "hello world", 11), 0);
	ASSERT_EQ(next_event(), nullptr);  // EOF is expected
}

class plugin_test_event_processor : public libsinsp::event_processor {
public:
	explicit plugin_test_event_processor(const char* ev_name) {
		num_async_evts = 0;
		event_name = ev_name;
	}

	void on_capture_start() override {}

	void process_event(sinsp_evt* evt, libsinsp::event_return rc) override {
		if(evt->get_type() == PPME_ASYNCEVENT_E) {
			// Retrieve internal event name
			auto ev_name = evt->get_param(1)->as<std::string>();
			if(ev_name == event_name) {
				num_async_evts++;
			}
		}
	}

	int num_async_evts;

private:
	std::string event_name;
};

// scenario: a plugin with dump capability is requested a dump and then the capture file is read.
// * register a plugin with async event capability
// * open inspector in no driver mode
// * request a scap file dump to a temporary text file
// * at this stage, the plugin will be requested to dump its state; in our test case, the plugin
// will just dump 10 fake events
// * open a replay inspector to read the generated scap file
// * register our event processor that just counts number of PPME_ASYNC_EVENT_E
// * remove the test scap file
// note: emscripten has trouble with the nodriver engine and async events
#if !defined(__EMSCRIPTEN__)
TEST_F(sinsp_with_test_input, plugin_dump) {
	register_plugin(&m_inspector, get_plugin_api_sample_syscall_async);

	// we will not use the test scap engine here, but open the src plugin instead
	// note: we configure the plugin to just emit 1 event through its open params
	m_inspector.open_nodriver();

	auto evt = next_event();
	ASSERT_NE(evt, nullptr);
	ASSERT_EQ(evt->get_type(), PPME_ASYNCEVENT_E);

	auto sinspdumper = sinsp_dumper();
	sinspdumper.open(&m_inspector, "test.scap", false);
	sinspdumper.close();

	m_inspector.close();

	// Here we open a replay inspector just to trigger the initstate events parsing
	auto replay_inspector = sinsp();
	//
	auto processor = plugin_test_event_processor("sampleticker");
	replay_inspector.register_external_event_processor(processor);
	ASSERT_NO_THROW(replay_inspector.open_savefile("test.scap"));

	ASSERT_EQ(processor.num_async_evts, 10);

	replay_inspector.close();
	remove("test.scap");
}
#endif

TEST(sinsp_plugin, plugin_extract_compatibility) {
	std::string tmp;
	sinsp i;
	plugin_api api;
	get_plugin_api_sample_plugin_extract(api);

	// compatible event sources specified, event types not specified
	api.get_name = []() { return "p1"; };
	auto p = i.register_plugin(&api);
	p->init("", tmp);
	ASSERT_EQ(p->extract_event_sources().size(), 1);
	ASSERT_TRUE(sinsp_plugin::is_source_compatible(p->extract_event_sources(), "sample"));
	ASSERT_FALSE(sinsp_plugin::is_source_compatible(p->extract_event_sources(),
	                                                sinsp_syscall_event_source_name));
	ASSERT_EQ(p->extract_event_codes().size(), 1);
	/* The plugin doesn't declare a list of event types and for this reason, it can extract only
	 * from pluginevent_e */
	ASSERT_TRUE(p->extract_event_codes().contains(PPME_PLUGINEVENT_E));
	ASSERT_FALSE(p->extract_event_codes().contains(PPME_SYSCALL_OPEN_X));

	// compatible event sources specified, event types specified (config-altered)
	api.get_name = []() { return "p1-2"; };
	p = i.register_plugin(&api);
	ASSERT_ANY_THROW(p->extract_event_codes());  // can't be called before init
	p->init("322,402", tmp);
	ASSERT_EQ(p->extract_event_sources().size(), 1);
	ASSERT_TRUE(sinsp_plugin::is_source_compatible(p->extract_event_sources(), "sample"));
	ASSERT_FALSE(sinsp_plugin::is_source_compatible(p->extract_event_sources(),
	                                                sinsp_syscall_event_source_name));
	ASSERT_EQ(p->extract_event_codes().size(), 2);
	ASSERT_TRUE(p->extract_event_codes().contains(PPME_PLUGINEVENT_E));
	ASSERT_TRUE(p->extract_event_codes().contains(PPME_ASYNCEVENT_E));
	ASSERT_FALSE(p->extract_event_codes().contains(PPME_SYSCALL_OPEN_X));

	// compatible event sources specified, event types specified
	api.get_name = []() { return "p2"; };
	api.get_extract_event_types = [](uint32_t* n, ss_plugin_t* s) {
		static uint16_t ret[] = {PPME_SYSCALL_OPEN_X};
		*n = sizeof(ret) / sizeof(uint16_t);
		return &ret[0];
	};
	p = i.register_plugin(&api);
	p->init("", tmp);
	ASSERT_EQ(p->extract_event_sources().size(), 1);
	ASSERT_TRUE(sinsp_plugin::is_source_compatible(p->extract_event_sources(), "sample"));
	ASSERT_FALSE(sinsp_plugin::is_source_compatible(p->extract_event_sources(),
	                                                sinsp_syscall_event_source_name));
	ASSERT_EQ(p->extract_event_codes().size(), 1);
	ASSERT_FALSE(p->extract_event_codes().contains(PPME_PLUGINEVENT_E));
	ASSERT_TRUE(p->extract_event_codes().contains(PPME_SYSCALL_OPEN_X));

	// compatible event sources not specified, event types not specified
	api.get_name = []() { return "p3"; };
	api.get_extract_event_sources = NULL;
	api.get_extract_event_types = NULL;
	p = i.register_plugin(&api);
	p->init("", tmp);
	ASSERT_EQ(p->extract_event_sources().size(), 0);
	ASSERT_TRUE(sinsp_plugin::is_source_compatible(p->extract_event_sources(), "sample"));
	ASSERT_TRUE(sinsp_plugin::is_source_compatible(p->extract_event_sources(),
	                                               sinsp_syscall_event_source_name));
	ASSERT_TRUE(p->extract_event_codes().contains(PPME_PLUGINEVENT_E));
	ASSERT_TRUE(p->extract_event_codes().contains(PPME_SYSCALL_OPEN_X));

	// compatible event sources not specified, event types not specified,
	// event sourcing capability is detected with specific event source
	plugin_api src_api;
	get_plugin_api_sample_plugin_source(src_api);
	api.get_name = []() { return "p4"; };
	api.get_id = src_api.get_id;
	api.get_event_source = src_api.get_event_source;
	api.open = src_api.open;
	api.close = src_api.close;
	api.next_batch = src_api.next_batch;
	p = i.register_plugin(&api);
	p->init("", tmp);
	ASSERT_EQ(p->extract_event_sources().size(), 1);
	ASSERT_TRUE(sinsp_plugin::is_source_compatible(p->extract_event_sources(), "sample"));
	ASSERT_FALSE(sinsp_plugin::is_source_compatible(p->extract_event_sources(),
	                                                sinsp_syscall_event_source_name));
	ASSERT_EQ(p->extract_event_codes().size(), 1);
	ASSERT_TRUE(p->extract_event_codes().contains(PPME_PLUGINEVENT_E));
	ASSERT_FALSE(p->extract_event_codes().contains(PPME_SYSCALL_OPEN_X));
}

// scenario: a plugin with event parsing capability and one with field
// extraction capability are loaded, both compatible with the "syscall"
// event source, and both consuming regular syscall events produced by
// any scap engine. The first is responsible of attaching an extra field to
// the sinsp thread table (a counter), and the latter extracts a field based
// on the value of the additional table's field.
TEST_F(sinsp_with_test_input, plugin_syscall_parse) {
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
	add_filtered_event_advance_ts(increasing_ts(),
	                              1,
	                              PPME_SYSCALL_OPEN_E,
	                              3,
	                              "/tmp/the_file",
	                              PPM_O_RDWR,
	                              0);
	auto evt = add_event_advance_ts(increasing_ts(),
	                                1,
	                                PPME_SYSCALL_OPEN_X,
	                                6,
	                                (uint64_t)3,
	                                "/tmp/the_file",
	                                PPM_O_RDWR,
	                                0,
	                                5,
	                                (uint64_t)123);
	ASSERT_EQ(get_field_as_string(evt, "sample.open_count", pl_flist), "2");
	ASSERT_EQ(get_field_as_string(evt, "sample.evt_count", pl_flist), "1");
	ASSERT_EQ(get_field_as_string(evt, "sample.tick", pl_flist), "false");

	evt = add_event_advance_ts(increasing_ts(),
	                           1,
	                           PPME_SYSCALL_INOTIFY_INIT1_X,
	                           2,
	                           (int64_t)12,
	                           (uint16_t)32);
	ASSERT_EQ(get_field_as_string(evt, "sample.open_count", pl_flist), "2");
	// the parsing plugin filters-out this kind of event, so there should be no counter for it
	ASSERT_EQ(get_field_as_string(evt, "sample.evt_count", pl_flist), "0");
	ASSERT_EQ(get_field_as_string(evt, "sample.tick", pl_flist), "false");

	// should extract NULL for ignored event codes, but should still parse it (because the parsing
	// plugin does not ignore it)
	evt = add_event_advance_ts(increasing_ts(),
	                           1,
	                           PPME_SYSCALL_OPEN_BY_HANDLE_AT_X,
	                           4,
	                           (uint64_t)4,
	                           (uint64_t)5,
	                           PPM_O_RDWR,
	                           "/tmp/the_file.txt");
	ASSERT_FALSE(field_has_value(evt, "sample.open_count", pl_flist));
	ASSERT_FALSE(field_has_value(evt, "sample.evt_count", pl_flist));
	ASSERT_FALSE(field_has_value(evt, "sample.tick", pl_flist));

	evt = add_event_advance_ts(increasing_ts(),
	                           1,
	                           PPME_SYSCALL_INOTIFY_INIT1_X,
	                           2,
	                           (int64_t)12,
	                           (uint16_t)32);
	ASSERT_EQ(get_field_as_string(evt, "sample.open_count", pl_flist), "3");
	ASSERT_EQ(get_field_as_string(evt, "sample.evt_count", pl_flist), "0");
	ASSERT_EQ(get_field_as_string(evt, "sample.tick", pl_flist), "false");

	evt = add_event_advance_ts(increasing_ts(),
	                           1,
	                           PPME_SYSCALL_OPEN_X,
	                           6,
	                           (uint64_t)4,
	                           "/tmp/the_file",
	                           PPM_O_RDWR,
	                           0,
	                           5,
	                           (uint64_t)123);
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
TEST_F(sinsp_with_test_input, plugin_syscall_async) {
	uint64_t max_count = 10;
	uint64_t period_ns = 1000000;  // 1ms
	/* async plugin config */
	std::string async_pl_cfg = std::to_string(max_count) + ":" + std::to_string(period_ns);
	std::string srcname = sinsp_syscall_event_source_name;

	sinsp_filter_check_list filterlist;
	register_plugin(&m_inspector, get_plugin_api_sample_syscall_async, async_pl_cfg);
	auto ext_pl = register_plugin(&m_inspector, get_plugin_api_sample_syscall_extract);
	add_plugin_filterchecks(&m_inspector, ext_pl, srcname, filterlist);

	// Check that the `sampleticker` async events was added to the list of events
	auto event_set =
	        libsinsp::events::names_to_event_set(std::unordered_set<std::string>{"sampleticker"});
	libsinsp::events::set<ppm_event_code> event_set_truth = {PPME_ASYNCEVENT_E};
	ASSERT_EQ(event_set.size(), 1);
	ASSERT_PPM_EVENT_CODES_EQ(event_set_truth, event_set);

	// check that the async event name is an accepted evt.type value
	std::unique_ptr<sinsp_filter_check> chk(
	        filterlist.new_filter_check_from_fldname("evt.type", &m_inspector, false));
	ASSERT_GT(chk->parse_field_name("evt.type", true, false), 0);
	ASSERT_NO_THROW(chk->add_filter_value("openat", strlen("openat") + 1, 0));
	ASSERT_NO_THROW(chk->add_filter_value("sampleticker", strlen("sampleticker") + 1, 1));
	ASSERT_ANY_THROW(chk->add_filter_value("badname", strlen("badname") + 1, 2));

	// we will not use the test scap engine here, but open the no-driver instead
	uint64_t count = 0;
	uint64_t cycles = 0;
	uint64_t max_cycles = max_count * 8;  // avoid infinite loops
	sinsp_evt* evt = NULL;
	int32_t rc = SCAP_SUCCESS;
	uint64_t last_ts = 0;
	m_inspector.open_nodriver();
	while(rc == SCAP_SUCCESS && cycles < max_cycles && count < max_count) {
		cycles++;
		rc = m_inspector.next(&evt);
		/* The no driver engine sends only `PPME_SCAPEVENT_E` events */
		if(rc == SCAP_TIMEOUT || evt->get_type() == PPME_SCAPEVENT_E) {
			// wait a bit so that the plugin can fire the async event
			std::this_thread::sleep_for(std::chrono::nanoseconds(period_ns));
			rc = SCAP_SUCCESS;
			continue;
		}
		count++;
		ASSERT_NE(evt, nullptr);
		ASSERT_EQ(evt->get_type(), PPME_ASYNCEVENT_E);
		ASSERT_EQ(evt->get_tid(), 1);
		ASSERT_EQ(evt->get_source_idx(), 0);  // "syscall" source
		ASSERT_EQ(std::string(evt->get_source_name()), srcname);
		if(cycles > 1) {
			ASSERT_GE(evt->get_ts(), last_ts);
		}
		ASSERT_FALSE(field_has_value(evt,
		                             "evt.pluginname",
		                             filterlist));  // not available for "syscall" async events
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
#endif  // !defined(__EMSCRIPTEN__)

// Scenario we load a plugin that parses any event and plays with the
// thread table, by stressing all the operations supported. After that, we
// also play with the plugin's table from the inspector C++ interface.
// Basically, we are verifying that the sinsp <-> plugin tables access
// is bidirectional and consistent.
TEST_F(sinsp_with_test_input, plugin_tables) {
	libsinsp::state::sinsp_table_owner owner;
	auto& reg = m_inspector.get_table_registry();

	add_default_init_thread();

	// the threads table is always present
	ASSERT_EQ(reg->tables().size(), 1);
	ASSERT_NE(reg->tables().find("threads"), reg->tables().end());

	// make sure we see a new table when we register the plugin
	ASSERT_EQ(reg->tables().find("plugin_sample"), reg->tables().end());
	ASSERT_EQ(reg->get_table<uint64_t>("plugin_sample"), nullptr);
	register_plugin(&m_inspector, get_plugin_api_sample_syscall_tables);
	ASSERT_EQ(reg->tables().size(), 2);
	ASSERT_NE(reg->tables().find("plugin_sample"), reg->tables().end());
	ASSERT_ANY_THROW(reg->get_table<uint8_t>("plugin_sample"));  // wrong key type
	ASSERT_NE(reg->get_table<uint64_t>("plugin_sample"), nullptr);

	// get the plugin table and check its fields and info
	auto table_wrapper = sinsp_table<uint64_t>(&owner, reg->get_table<uint64_t>("plugin_sample"));
	auto table = &table_wrapper;
	ASSERT_EQ(table->name(), std::string("plugin_sample"));
	ASSERT_EQ(table->entries_count(), 0);
	ASSERT_EQ(table->key_info(), libsinsp::state::typeinfo::of<uint64_t>());
	ASSERT_EQ(table->fields().size(), 1);

	// get an already existing field form the plugin table
	auto field_info = table->get_field_info("u64_val");
	ASSERT_NE(field_info, nullptr);
	ASSERT_EQ(field_info->read_only, false);
	ASSERT_EQ(field_info->field_type, ss_plugin_state_type::SS_PLUGIN_ST_UINT64);

	// add a new field in the plugin table
	table->add_field<std::string>("str_val");
	field_info = table->get_field_info("str_val");
	ASSERT_NE(field_info, nullptr);
	ASSERT_EQ(field_info->read_only, false);
	ASSERT_EQ(field_info->field_type, ss_plugin_state_type::SS_PLUGIN_ST_STRING);

	// we open a capture and iterate, so that we make sure that all
	// the state operations keep working at every round of the loop
	open_inspector();
	const char* asyncname = "sampleasync";
	const char* sample_plugin_evtdata = "hello world";
	uint64_t max_iterations = 10000;
	for(uint64_t i = 0; i < max_iterations; i++) {
		auto evt = add_event_advance_ts(
		        increasing_ts(),
		        1,
		        PPME_ASYNCEVENT_E,
		        3,
		        (uint32_t)0,
		        asyncname,
		        scap_const_sized_buffer{sample_plugin_evtdata, strlen(sample_plugin_evtdata) + 1});
		ASSERT_EQ(evt->get_type(), PPME_ASYNCEVENT_E);
		ASSERT_EQ(evt->get_source_idx(), 0);
	}

	// we play around with the plugin's table, like if it was a C++ one from sinsp
	auto sfieldacc = table->get_field<uint64_t>("u64_val");
	auto dfieldacc = table->get_field<std::string>("str_val");

	for(uint64_t i = 0; i < max_iterations; i++) {
		ASSERT_EQ(table->entries_count(), i);

		// get non-existing entry
		ASSERT_ANY_THROW(table->get_entry(i));

		// creating a destroying a thread without adding it to the table
		table->new_entry();

		// creating and adding a thread to the table
		auto e = table->new_entry();
		table->add_entry(i, e);
		table->get_entry(i);
		ASSERT_EQ(table->entries_count(), i + 1);

		// read and write from newly-created thread (existing field)
		uint64_t tmpu64 = (uint64_t)-1;
		e.read_field(sfieldacc, tmpu64);
		ASSERT_EQ(tmpu64, 0);
		tmpu64 = 5;
		e.write_field(sfieldacc, tmpu64);
		tmpu64 = 0;
		e.read_field(sfieldacc, tmpu64);
		ASSERT_EQ(tmpu64, 5);

		// read and write from newly-created thread (added field)
		std::string tmpstr = "test";
		e.read_field(dfieldacc, tmpstr);
		ASSERT_EQ(tmpstr, "");
		tmpstr = "hello";
		e.write_field(dfieldacc, tmpstr);
		tmpstr = "";
		e.read_field(dfieldacc, tmpstr);
		ASSERT_EQ(tmpstr, "hello");
	}

	// full iteration
	auto it = [&](sinsp_table_entry& e) -> bool {
		uint64_t tmpu64;
		std::string tmpstr;
		e.read_field(sfieldacc, tmpu64);
		EXPECT_EQ(tmpu64, 5);
		e.read_field(dfieldacc, tmpstr);
		EXPECT_EQ(tmpstr, "hello");
		return true;
	};
	ASSERT_TRUE(table->foreach_entry(it));

	// iteration with break-out
	ASSERT_FALSE(table->foreach_entry([&](sinsp_table_entry& e) -> bool { return false; }));

	// iteration with error
	ASSERT_ANY_THROW(table->foreach_entry(
	        [&](sinsp_table_entry& e) -> bool { throw sinsp_exception("some error"); }));

	// erasing an unknown thread
	ASSERT_ANY_THROW(table->erase_entry(max_iterations));
	ASSERT_EQ(table->entries_count(), max_iterations);

	// erase one of the newly-created thread
	table->erase_entry(0);
	ASSERT_EQ(table->entries_count(), max_iterations - 1);

	// clear all
	ASSERT_NO_THROW(table->clear_entries());
	ASSERT_EQ(table->entries_count(), 0);
}

TEST_F(sinsp_with_test_input, plugin_subtables) {
	const constexpr auto num_entries_from_plugin = 1024;

	auto& reg = m_inspector.get_table_registry();

	register_plugin(&m_inspector, get_plugin_api_sample_syscall_subtables);

	auto table = dynamic_cast<libsinsp::state::extensible_table<int64_t>*>(
	        reg->get_table<int64_t>("threads"));
	ASSERT_NE(table, nullptr);
	ASSERT_EQ(table->name(), std::string("threads"));
	ASSERT_EQ(table->entries_count(), 0);
	ASSERT_EQ(table->key_info(), libsinsp::state::typeinfo::of<int64_t>());
	ASSERT_EQ(table->dynamic_fields()->fields().size(), 0);

	auto field = table->static_fields()->find("file_descriptors");
	ASSERT_NE(field, table->static_fields()->end());
	ASSERT_EQ(field->second.readonly(), true);
	ASSERT_EQ(field->second.valid(), true);
	ASSERT_EQ(field->second.name(), "file_descriptors");
	ASSERT_EQ(field->second.info(), libsinsp::state::typeinfo::of<libsinsp::state::base_table*>());

	ASSERT_EQ(table->entries_count(), 0);

	// start the event capture
	// we coordinate with the plugin by sending open events: for each one received,
	// the plugin will take a subsequent action on which we then assert the status
	// note: we need to do this before adding our artificial threadinfo because
	// the threads table is cleared up upon inspectors being opened
	open_inspector();

	// add a new entry to the thread table
	int64_t tid = 5;
	ASSERT_NE(table->add_entry(tid, table->new_entry()), nullptr);
	auto entry = table->get_entry(tid);
	ASSERT_NE(entry, nullptr);
	ASSERT_EQ(table->entries_count(), 1);

	// obtain a pointer to the subtable (check typing too)
	auto subtable_acc = field->second.new_accessor<libsinsp::state::base_table*>();
	auto subtable = dynamic_cast<sinsp_fdtable*>(entry->read_field(*subtable_acc));
	ASSERT_NE(subtable, nullptr);
	ASSERT_EQ(subtable->name(), std::string("file_descriptors"));
	ASSERT_EQ(subtable->entries_count(), 0);

	// get an accessor to one of the static fields
	auto sfield = subtable->static_fields()->find("pid");
	ASSERT_NE(sfield, subtable->static_fields()->end());
	ASSERT_EQ(sfield->second.readonly(), false);
	ASSERT_EQ(sfield->second.valid(), true);
	ASSERT_EQ(sfield->second.name(), "pid");
	ASSERT_EQ(sfield->second.info(), libsinsp::state::typeinfo::of<int64_t>());
	auto sfieldacc = sfield->second.new_accessor<int64_t>();

	// get an accessor to a dynamic field declared by the plugin
	ASSERT_EQ(subtable->dynamic_fields()->fields().size(), 1);
	auto dfield = subtable->dynamic_fields()->fields().find("custom");
	ASSERT_NE(dfield, subtable->dynamic_fields()->fields().end());
	auto dfieldacc = dfield->second.new_accessor<std::string>();

	// step #0: the plugin should populate the fdtable
	add_event_advance_ts(increasing_ts(),
	                     tid,
	                     PPME_SYSCALL_OPEN_X,
	                     6,
	                     (int64_t)3,
	                     "/tmp/the_file",
	                     PPM_O_RDWR,
	                     (uint32_t)0,
	                     (uint32_t)0,
	                     (uint64_t)0);
	ASSERT_EQ(subtable->entries_count(), num_entries_from_plugin);

	auto itt = [&](libsinsp::state::table_entry& e) -> bool {
		int64_t tmp;
		std::string tmpstr;
		e.read_field(*sfieldacc, tmp);
		EXPECT_EQ(tmp, 123);
		e.read_field(*dfieldacc, tmpstr);
		EXPECT_EQ(tmpstr, "world");
		return true;
	};
	ASSERT_TRUE(subtable->foreach_entry(itt));

	// step #1: the plugin should remove one entry from the fdtable
	add_event_advance_ts(increasing_ts(),
	                     tid,
	                     PPME_SYSCALL_OPEN_X,
	                     6,
	                     (int64_t)3,
	                     "/tmp/the_file",
	                     PPM_O_RDWR,
	                     (uint32_t)0,
	                     (uint32_t)0,
	                     (uint64_t)0);
	ASSERT_EQ(subtable->entries_count(), num_entries_from_plugin - 1);

	// step #2: the plugin should cleae the fdtable
	add_event_advance_ts(increasing_ts(),
	                     tid,
	                     PPME_SYSCALL_OPEN_X,
	                     6,
	                     (int64_t)3,
	                     "/tmp/the_file",
	                     PPM_O_RDWR,
	                     (uint32_t)0,
	                     (uint32_t)0,
	                     (uint64_t)0);
	ASSERT_EQ(subtable->entries_count(), 0);
}

TEST_F(sinsp_with_test_input, plugin_subtables_array) {
	const constexpr auto num_entries_from_plugin = 10;

	auto& reg = m_inspector.get_table_registry();

	register_plugin(&m_inspector, get_plugin_api_sample_syscall_subtables_array);

	auto table = dynamic_cast<libsinsp::state::extensible_table<int64_t>*>(
	        reg->get_table<int64_t>("threads"));
	ASSERT_NE(table, nullptr);
	ASSERT_EQ(table->name(), std::string("threads"));
	ASSERT_EQ(table->entries_count(), 0);
	ASSERT_EQ(table->key_info(), libsinsp::state::typeinfo::of<int64_t>());
	ASSERT_EQ(table->dynamic_fields()->fields().size(), 0);

	auto field = table->static_fields()->find("env");
	ASSERT_NE(field, table->static_fields()->end());
	ASSERT_EQ(field->second.readonly(), true);
	ASSERT_EQ(field->second.valid(), true);
	ASSERT_EQ(field->second.name(), "env");
	ASSERT_EQ(field->second.info(), libsinsp::state::typeinfo::of<libsinsp::state::base_table*>());

	ASSERT_EQ(table->entries_count(), 0);

	// start the event capture
	// we coordinate with the plugin by sending open events: for each one received,
	// the plugin will take a subsequent action on which we then assert the status
	// note: we need to do this before adding our artificial threadinfo because
	// the threads table is cleared up upon inspectors being opened
	open_inspector();

	// add a new entry to the thread table
	int64_t tid = 5;
	ASSERT_NE(table->add_entry(tid, table->new_entry()), nullptr);
	auto entry = table->get_entry(tid);
	ASSERT_NE(entry, nullptr);
	ASSERT_EQ(table->entries_count(), 1);

	// obtain a pointer to the subtable (check typing too)
	auto subtable_acc = field->second.new_accessor<libsinsp::state::base_table*>();
	auto subtable =
	        dynamic_cast<libsinsp::state::stl_container_table_adapter<std::vector<std::string>>*>(
	                entry->read_field(*subtable_acc));
	ASSERT_NE(subtable, nullptr);
	ASSERT_EQ(subtable->name(), std::string("env"));
	ASSERT_EQ(subtable->entries_count(), 0);

	// get an accessor to a dynamic field representing the array's values
	ASSERT_EQ(subtable->dynamic_fields()->fields().size(), 1);
	auto dfield = subtable->dynamic_fields()->fields().find("value");
	ASSERT_NE(dfield, subtable->dynamic_fields()->fields().end());
	ASSERT_EQ(dfield->second.readonly(), false);
	ASSERT_EQ(dfield->second.valid(), true);
	ASSERT_EQ(dfield->second.name(), "value");
	ASSERT_EQ(dfield->second.info(), libsinsp::state::typeinfo::of<std::string>());
	auto dfieldacc = dfield->second.new_accessor<std::string>();

	// step #0: the plugin should populate the fdtable
	add_event_advance_ts(increasing_ts(),
	                     tid,
	                     PPME_SYSCALL_OPEN_X,
	                     6,
	                     (int64_t)3,
	                     "/tmp/the_file",
	                     PPM_O_RDWR,
	                     (uint32_t)0,
	                     (uint32_t)0,
	                     (uint64_t)0);
	ASSERT_EQ(subtable->entries_count(), num_entries_from_plugin);

	auto itt = [&](libsinsp::state::table_entry& e) -> bool {
		std::string tmpstr;
		e.read_field(*dfieldacc, tmpstr);
		EXPECT_EQ(tmpstr, "hello");
		return true;
	};
	ASSERT_TRUE(subtable->foreach_entry(itt));

	// step #1: the plugin should remove one entry from the fdtable
	add_event_advance_ts(increasing_ts(),
	                     tid,
	                     PPME_SYSCALL_OPEN_X,
	                     6,
	                     (int64_t)3,
	                     "/tmp/the_file",
	                     PPM_O_RDWR,
	                     (uint32_t)0,
	                     (uint32_t)0,
	                     (uint64_t)0);
	ASSERT_EQ(subtable->entries_count(), num_entries_from_plugin - 1);

	// step #2: the plugin should cleae the fdtable
	add_event_advance_ts(increasing_ts(),
	                     tid,
	                     PPME_SYSCALL_OPEN_X,
	                     6,
	                     (int64_t)3,
	                     "/tmp/the_file",
	                     PPM_O_RDWR,
	                     (uint32_t)0,
	                     (uint32_t)0,
	                     (uint64_t)0);
	ASSERT_EQ(subtable->entries_count(), 0);
}

TEST_F(sinsp_with_test_input, plugin_subtables_array_pair) {
	const constexpr auto num_entries_from_plugin = 10;

	auto& reg = m_inspector.get_table_registry();

	register_plugin(&m_inspector, get_plugin_api_sample_syscall_subtables_array_pair);

	auto table = dynamic_cast<libsinsp::state::extensible_table<int64_t>*>(
	        reg->get_table<int64_t>("threads"));
	ASSERT_NE(table, nullptr);
	ASSERT_EQ(table->name(), std::string("threads"));
	ASSERT_EQ(table->entries_count(), 0);
	ASSERT_EQ(table->key_info(), libsinsp::state::typeinfo::of<int64_t>());
	ASSERT_EQ(table->dynamic_fields()->fields().size(), 0);

	// Test "cgroups" field
	auto field = table->static_fields()->find("cgroups");
	ASSERT_NE(field, table->static_fields()->end());
	ASSERT_EQ(field->second.readonly(), true);
	ASSERT_EQ(field->second.valid(), true);
	ASSERT_EQ(field->second.name(), "cgroups");
	ASSERT_EQ(field->second.info(), libsinsp::state::typeinfo::of<libsinsp::state::base_table*>());

	ASSERT_EQ(table->entries_count(), 0);

	// start the event capture
	// we coordinate with the plugin by sending open events: for each one received,
	// the plugin will take a subsequent action on which we then assert the status
	// note: we need to do this before adding our artificial threadinfo because
	// the threads table is cleared up upon inspectors being opened
	open_inspector();

	// add a new entry to the thread table
	int64_t tid = 5;
	ASSERT_NE(table->add_entry(tid, table->new_entry()), nullptr);
	auto entry = table->get_entry(tid);
	ASSERT_NE(entry, nullptr);
	ASSERT_EQ(table->entries_count(), 1);

	// obtain a pointer to the subtable (check typing too)
	auto subtable_acc = field->second.new_accessor<libsinsp::state::base_table*>();
	auto subtable = dynamic_cast<libsinsp::state::stl_container_table_adapter<
	        std::vector<std::pair<std::string, std::string>>,
	        libsinsp::state::pair_table_entry_adapter<std::string, std::string>>*>(
	        entry->read_field(*subtable_acc));
	ASSERT_NE(subtable, nullptr);
	ASSERT_EQ(subtable->name(), std::string("cgroups"));
	ASSERT_EQ(subtable->entries_count(), 0);
	// get an accessor to a dynamic field representing the array's values
	ASSERT_EQ(subtable->dynamic_fields()->fields().size(), 2);  // pair.first, pair.second

	auto dfield_first = subtable->dynamic_fields()->fields().find("first");
	ASSERT_NE(dfield_first, subtable->dynamic_fields()->fields().end());
	ASSERT_EQ(dfield_first->second.readonly(), false);
	ASSERT_EQ(dfield_first->second.valid(), true);
	ASSERT_EQ(dfield_first->second.name(), "first");
	ASSERT_EQ(dfield_first->second.info(), libsinsp::state::typeinfo::of<std::string>());
	auto dfield_first_acc = dfield_first->second.new_accessor<std::string>();

	auto dfield_second = subtable->dynamic_fields()->fields().find("second");
	ASSERT_NE(dfield_second, subtable->dynamic_fields()->fields().end());
	ASSERT_EQ(dfield_second->second.readonly(), false);
	ASSERT_EQ(dfield_second->second.valid(), true);
	ASSERT_EQ(dfield_second->second.name(), "second");
	ASSERT_EQ(dfield_second->second.info(), libsinsp::state::typeinfo::of<std::string>());
	auto dfield_second_acc = dfield_second->second.new_accessor<std::string>();

	// step #0: the plugin should populate the fdtable
	add_event_advance_ts(increasing_ts(),
	                     tid,
	                     PPME_SYSCALL_OPEN_X,
	                     6,
	                     (int64_t)3,
	                     "/tmp/the_file",
	                     PPM_O_RDWR,
	                     (uint32_t)0,
	                     (uint32_t)0,
	                     (uint64_t)0);
	ASSERT_EQ(subtable->entries_count(), num_entries_from_plugin);

	auto itt = [&](libsinsp::state::table_entry& e) -> bool {
		std::string first, second;
		e.read_field(*dfield_first_acc, first);
		e.read_field(*dfield_second_acc, second);
		EXPECT_EQ(first, "hello");
		EXPECT_EQ(second, "world");
		return true;
	};
	ASSERT_TRUE(subtable->foreach_entry(itt));

	// step #1: the plugin should remove one entry from the fdtable
	add_event_advance_ts(increasing_ts(),
	                     tid,
	                     PPME_SYSCALL_OPEN_X,
	                     6,
	                     (int64_t)3,
	                     "/tmp/the_file",
	                     PPM_O_RDWR,
	                     (uint32_t)0,
	                     (uint32_t)0,
	                     (uint64_t)0);
	ASSERT_EQ(subtable->entries_count(), num_entries_from_plugin - 1);

	// step #2: the plugin should cleae the fdtable
	add_event_advance_ts(increasing_ts(),
	                     tid,
	                     PPME_SYSCALL_OPEN_X,
	                     6,
	                     (int64_t)3,
	                     "/tmp/the_file",
	                     PPM_O_RDWR,
	                     (uint32_t)0,
	                     (uint32_t)0,
	                     (uint64_t)0);
	ASSERT_EQ(subtable->entries_count(), 0);
}

// Scenario: we load a plugin expecting it to log
// when it's initialized and destroyed.
// We use a callback attached to the logger to assert the message.
// When the inspector goes out of scope,
// the plugin is automatically destroyed.
TEST(sinsp_plugin, plugin_logging) {
	{
		std::string tmp;
		sinsp i;
		plugin_api api;
		get_plugin_api_sample_plugin_extract(api);

		// the plugin is logging with a NULL component, so we expect the component to fallback to
		// the plugin name
		api.get_name = []() { return "plugin_name"; };

		libsinsp_logger()->add_callback_log([](std::string&& str, sinsp_logger::severity sev) {
			std::string expected = "plugin_name: initializing plugin...";
			ASSERT_TRUE(std::equal(expected.rbegin(), expected.rend(), str.rbegin()));
		});

		auto p = i.register_plugin(&api);
		p->init("", tmp);

		libsinsp_logger()->remove_callback_log();
		libsinsp_logger()->add_callback_log([](std::string&& str, sinsp_logger::severity sev) {
			std::string expected = "plugin_name: destroying plugin...";
			ASSERT_TRUE(std::equal(expected.rbegin(), expected.rend(), str.rbegin()));
		});
	}

	libsinsp_logger()->remove_callback_log();
}

// Scenario: we provide the plugin with a new configuration,
// expecting it to log when it's notified.
TEST(sinsp_plugin, plugin_set_config) {
	std::string tmp;
	sinsp i;
	plugin_api api;
	get_plugin_api_sample_plugin_extract(api);

	api.get_name = []() { return "plugin_name"; };

	auto p = i.register_plugin(&api);
	p->init("", tmp);

	libsinsp_logger()->add_callback_log([](std::string&& str, sinsp_logger::severity sev) {
		std::string expected = "plugin_name: new config!";
		ASSERT_TRUE(std::equal(expected.rbegin(), expected.rend(), str.rbegin()));
	});

	ASSERT_TRUE(p->set_config("some config"));

	libsinsp_logger()->remove_callback_log();
}

TEST_F(sinsp_with_test_input, plugin_metrics) {
	uint32_t test_metrics_flags = (METRICS_V2_PLUGINS);
	libs::metrics::libs_metrics_collector libs_metrics_collector(&m_inspector, test_metrics_flags);

	libs_metrics_collector.snapshot();
	auto metrics_snapshot = libs_metrics_collector.get_metrics();
	ASSERT_EQ(metrics_snapshot.size(), 0);

	register_plugin(&m_inspector, get_plugin_api_sample_metrics);
	open_inspector();

	libs_metrics_collector.snapshot();
	metrics_snapshot = libs_metrics_collector.get_metrics();
	ASSERT_EQ(metrics_snapshot.size(), 2);

	int events = 256;
	for(int i = 0; i < events; i++) {
		add_event_advance_ts(increasing_ts(),
		                     0,
		                     PPME_SYSCALL_OPEN_X,
		                     6,
		                     (int64_t)3,
		                     "/tmp/the_file",
		                     PPM_O_RDWR,
		                     (uint32_t)0,
		                     (uint32_t)0,
		                     (uint64_t)0);
	}

	libs_metrics_collector.snapshot();
	metrics_snapshot = libs_metrics_collector.get_metrics();
	ASSERT_EQ(metrics_snapshot.size(), 2);

	ASSERT_EQ(std::string(metrics_snapshot.at(0).name), "sample_metrics.dummy_metric");
	ASSERT_EQ(std::string(metrics_snapshot.at(1).name), "sample_metrics.evt_count");

	ASSERT_EQ(metrics_snapshot.back().value.u64, events);
}

#if defined(ENABLE_THREAD_POOL) && !defined(__EMSCRIPTEN__)

TEST_F(sinsp_with_test_input, plugin_routines) {
	auto p = register_plugin(&m_inspector, get_plugin_api_sample_routines);
	open_inspector();

	auto tp = m_inspector.get_thread_pool();

	ASSERT_NE(tp, nullptr);

	// step #0: the plugins subscribes a routine on capture open
	auto routines_num = tp->routines_num();
	ASSERT_EQ(routines_num, 1);

	// step #1: the plugin subscribes another routine
	add_event_advance_ts(increasing_ts(),
	                     0,
	                     PPME_SYSCALL_OPEN_X,
	                     6,
	                     (int64_t)3,
	                     "/tmp/the_file",
	                     PPM_O_RDWR,
	                     (uint32_t)0,
	                     (uint32_t)0,
	                     (uint64_t)0);
	routines_num = tp->routines_num();
	ASSERT_EQ(routines_num, 2);

	// step #2: the plugin unsubscribes the previous routine
	add_event_advance_ts(increasing_ts(),
	                     0,
	                     PPME_SYSCALL_OPEN_X,
	                     6,
	                     (int64_t)3,
	                     "/tmp/the_file",
	                     PPM_O_RDWR,
	                     (uint32_t)0,
	                     (uint32_t)0,
	                     (uint64_t)0);
	routines_num = tp->routines_num();
	ASSERT_EQ(routines_num, 1);

	// step #3: the plugin subscribes another routine
	add_event_advance_ts(increasing_ts(),
	                     0,
	                     PPME_SYSCALL_OPEN_X,
	                     6,
	                     (int64_t)3,
	                     "/tmp/the_file",
	                     PPM_O_RDWR,
	                     (uint32_t)0,
	                     (uint32_t)0,
	                     (uint64_t)0);
	routines_num = tp->routines_num();
	ASSERT_EQ(routines_num, 2);

	// step #4: the plugin sets a flag that causes the previous routine to be unsubscibed
	add_event_advance_ts(increasing_ts(),
	                     0,
	                     PPME_SYSCALL_OPEN_X,
	                     6,
	                     (int64_t)3,
	                     "/tmp/the_file",
	                     PPM_O_RDWR,
	                     (uint32_t)0,
	                     (uint32_t)0,
	                     (uint64_t)0);
	std::this_thread::sleep_for(
	        std::chrono::milliseconds(100));  // wait for a bit to let routine finish
	routines_num = tp->routines_num();
	ASSERT_EQ(routines_num, 1);

	// step: #5: the plugin doesn't unsubscribe the last routine, but the thread pool shuould
	// unsubscribe it on capture close
	m_inspector.close();
	std::this_thread::sleep_for(
	        std::chrono::milliseconds(100));  // wait for a bit to let routine finish
	routines_num = tp->routines_num();
	ASSERT_EQ(routines_num, 0);
}

// Schema version validation tests
struct schema_version_test_case {
	std::string test_name;
	std::function<void(plugin_api&)> plugin_api_func;
	std::string config;
	sinsp_version test_version;
	bool expected_success;
	std::string expected_error_substring;

	friend std::ostream& operator<<(std::ostream& os, const schema_version_test_case& test_case) {
		os << "Test case: " << test_case.test_name
		   << ", Test version: " << test_case.test_version.as_string()
		   << ", Expected success: " << std::boolalpha << test_case.expected_success
		   << ", Expected error substring: " << test_case.expected_error_substring;
		return os;
	}
};

class schema_version_test : public sinsp_with_test_input,
                            public ::testing::WithParamInterface<schema_version_test_case> {};

TEST_P(schema_version_test, plugin_schema_version_validation) {
	const auto& param = GetParam();

	auto pl = register_plugin(&m_inspector, param.plugin_api_func, param.config);
	std::string err;
	bool result = pl->check_required_schema_version(param.test_version, err);

	ASSERT_EQ(result, param.expected_success) << "Test: " << param.test_name;

	if(!param.expected_success) {
		ASSERT_TRUE(err.find(param.expected_error_substring) != std::string::npos)
		        << "Test: " << param.test_name << ", Error: " << err
		        << ", Expected substring: " << param.expected_error_substring;
	} else {
		ASSERT_TRUE(err.empty()) << "Test: " << param.test_name << ", Unexpected error: " << err;
	}
}

INSTANTIATE_TEST_CASE_P(
        plugin_schema_version_validation,
        schema_version_test,
        ::testing::Values(
                // Default compatible tests
                schema_version_test_case{"default_compatible",
                                         get_plugin_api_sample_extract_schema_version,
                                         "",
                                         sinsp_version("3.0.0"),
                                         true,
                                         ""},
                schema_version_test_case{"no_required_schema_version",
                                         get_plugin_api_sample_no_required_schema_version,
                                         "{}",
                                         sinsp_version("3.0.0"),
                                         true,
                                         ""},
                // Extract plugin tests
                schema_version_test_case{"extract_compatible_explicit",
                                         get_plugin_api_sample_extract_schema_version,
                                         R"({"required_schema_version": "3.69.0"})",
                                         sinsp_version(3, 69, 0),
                                         true,
                                         ""},
                schema_version_test_case{"extract_major_incompatible",
                                         get_plugin_api_sample_extract_schema_version,
                                         R"({"required_schema_version": "4.0.0"})",
                                         sinsp_version(3, 0, 0),
                                         false,
                                         "major versions disagree"},
                schema_version_test_case{"extract_minor_incompatible",
                                         get_plugin_api_sample_extract_schema_version,
                                         R"({"required_schema_version": "3.1.0"})",
                                         sinsp_version(3, 0, 0),
                                         false,
                                         "minor version is less than the requested one"},
                schema_version_test_case{"extract_patch_incompatible",
                                         get_plugin_api_sample_extract_schema_version,
                                         R"({"required_schema_version": "3.0.1"})",
                                         sinsp_version(3, 0, 0),
                                         false,
                                         "patch version is less than the requested one"},
                schema_version_test_case{"extract_invalid_format",
                                         get_plugin_api_sample_extract_schema_version,
                                         R"({"required_schema_version": "invalid.version"})",
                                         sinsp_version("invalid.version"),
                                         false,
                                         "invalid required event schema version"},
                // Parse plugin tests
                schema_version_test_case{"parse_compatible_explicit",
                                         get_plugin_api_sample_parse_schema_version,
                                         R"({"required_schema_version": "3.0.0"})",
                                         sinsp_version(3, 0, 0),
                                         true,
                                         ""},
                schema_version_test_case{
                        "parse_custom_event_types",
                        get_plugin_api_sample_parse_schema_version,
                        R"({"required_schema_version": "3.0.0", "event_types": [110, 322]})",
                        sinsp_version(3, 0, 0),
                        true,
                        ""},
                schema_version_test_case{"parse_major_incompatible",
                                         get_plugin_api_sample_parse_schema_version,
                                         R"({"required_schema_version": "4.0.0"})",
                                         sinsp_version(3, 0, 0),
                                         false,
                                         "major versions disagree"},
                schema_version_test_case{"parse_minor_incompatible",
                                         get_plugin_api_sample_parse_schema_version,
                                         R"({"required_schema_version": "3.1.0"})",
                                         sinsp_version(3, 0, 0),
                                         false,
                                         "minor version is less than the requested one"},
                schema_version_test_case{"parse_patch_incompatible",
                                         get_plugin_api_sample_parse_schema_version,
                                         R"({"required_schema_version": "3.0.1"})",
                                         sinsp_version(3, 0, 0),
                                         false,
                                         "patch version is less than the requested one"},
                schema_version_test_case{"parse_invalid_format",
                                         get_plugin_api_sample_parse_schema_version,
                                         R"({"required_schema_version": "invalid.version"})",
                                         sinsp_version("invalid.version"),
                                         false,
                                         "invalid required event schema version"},
                schema_version_test_case{"defaut_schema_version_compatible",
                                         get_plugin_api_sample_extract_schema_version,
                                         "",
                                         sinsp_version("3.0.0"),
                                         true,
                                         ""},
                schema_version_test_case{"defaut_schema_version_custom_event_source",
                                         get_plugin_api_sample_custom_event_sources,
                                         R"({"required_schema_version": "2.0.0"})",
                                         sinsp_version("3.0.0"),
                                         true,
                                         ""}),
        [](const ::testing::TestParamInfo<schema_version_test_case>& info) {
	        return info.param.test_name;
        });

#endif

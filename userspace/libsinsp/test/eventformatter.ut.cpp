// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2026 The Falco Authors.

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

#include <libsinsp/sinsp.h>
#include <libsinsp/eventformatter.h>

#include <gtest/gtest.h>

#include <sinsp_with_test_input.h>

#include <memory>
#include <vector>
#include <string>
#include <iostream>

static std::string pretty_print(const std::map<std::string, std::string>& in) {
	std::string ret = "(";
	for(const auto& v : in) {
		ret.append(" {'").append(v.first).append("','").append(v.second).append("'}");
	}
	return ret.append(" )");
}

class sinsp_formatter_test : public sinsp_with_test_input {
public:
	void SetUp() override {
		sinsp_with_test_input::SetUp();
		add_default_init_thread();
		open_inspector();
	}

	void format(
	        const std::string& fmt,
	        sinsp_evt_formatter::output_format of = sinsp_evt_formatter::output_format::OF_NORMAL,
	        bool resolve_transformers = true,
	        int64_t tid_caller = INIT_TID) {
		sinsp_evt_formatter f(&m_inspector, fmt, m_filter_list);
		f.set_resolve_transformed_fields(resolve_transformers);
		auto evt = generate_getcwd_failed_entry_event(tid_caller);
		f.get_field_names(m_last_field_names);
		auto r1 = f.resolve_tokens(evt, m_last_field_values);
		auto r2 = f.tostring_withformat(evt, m_last_output, of);
		m_last_res = r1 && r2;
	}

	bool m_last_res = false;
	std::string m_last_output;
	std::vector<std::string> m_last_field_names;
	std::map<std::string, std::string> m_last_field_values;

	sinsp_filter_check_list m_filter_list;
};

TEST_F(sinsp_formatter_test, field_names) {
	format("this is a sample output %proc.name %fd.type %proc.pid");
	EXPECT_EQ(m_last_field_names.size(), 3);
	EXPECT_NE(find(m_last_field_names.begin(), m_last_field_names.end(), "proc.name"),
	          m_last_field_names.end());
	EXPECT_NE(find(m_last_field_names.begin(), m_last_field_names.end(), "fd.type"),
	          m_last_field_names.end());
	EXPECT_NE(find(m_last_field_names.begin(), m_last_field_names.end(), "proc.pid"),
	          m_last_field_names.end());
}

TEST_F(sinsp_formatter_test, invalid_tokens) {
	EXPECT_THROW(format("start %some.field end"), sinsp_exception);
	EXPECT_THROW(format("start %a end"), sinsp_exception);
	EXPECT_THROW(format("start % end"), sinsp_exception);
	EXPECT_THROW(format("start %proc.name %"), sinsp_exception);
}

TEST_F(sinsp_formatter_test, field) {
	format("start %proc.name end");
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "start init end");
	EXPECT_EQ(m_last_field_values.size(), 1) << pretty_print(m_last_field_values);
	EXPECT_EQ(m_last_field_values["proc.name"], "init");
}

TEST_F(sinsp_formatter_test, field_json) {
	format("start %proc.name end", sinsp_evt_formatter::output_format::OF_JSON);
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "{\"proc.name\":\"init\"}");
	EXPECT_EQ(m_last_field_values.size(), 1) << pretty_print(m_last_field_values);
	EXPECT_EQ(m_last_field_values["proc.name"], "init");
}

TEST_F(sinsp_formatter_test, json_utf8_strings) {
	struct test_case {
		const char* name;
		std::string input;
		std::string expected;
	};
	// Literal expected bytes are independent of the sanitizer under test.
	const std::vector<test_case> cases = {
	        {"ascii", "ordinary", "ordinary"},
	        {"unicode",
	         "caf\xc3\xa9_\xe2\x98\x83_\xf0\x9f\x98\x80",
	         "caf\xc3\xa9_\xe2\x98\x83_\xf0\x9f\x98\x80"},
	        {"invalid_lead", "a\xffz", "a\xef\xbf\xbdz"},
	        {"continuation", "a\x80z", "a\xef\xbf\xbdz"},
	        {"truncated", "a\xe2\x82", "a\xef\xbf\xbd"},
	        {"overlong", "a\xc0\xafz", "a\xef\xbf\xbd\xef\xbf\xbdz"},
	        {"surrogate", "a\xed\xa0\x80z", "a\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbdz"},
	        {"out_of_range",
	         "a\xf4\x90\x80\x80z",
	         "a\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbdz"},
	        {"bad_continuation", "a\xe2(\xa1z", "a\xef\xbf\xbd(\xef\xbf\xbdz"},
	        {"newline", "a\nz", "a\nz"},
	        {"carriage_return", "a\rz", "a\rz"},
	        {"tab", "a\tz", "a\tz"},
	        {"escape", "a\x1b[31mz", "a\x1b[31mz"},
	        {"other_controls", "a\x01\x07\x08\x0b\x0cz", "a\x01\x07\x08\x0b\x0cz"},
	        {"quotes_backslash", "a\"\\z", "a\"\\z"},
	        {"mixed", "a\xff\n\"\\\xe2\x82z", "a\xef\xbf\xbd\n\"\\\xef\xbf\xbdz"},
	        {"healthy_after", "still_working", "still_working"},
	};
	sinsp_evt_formatter formatter(&m_inspector, "%proc.args", m_filter_list);
	for(const auto& test : cases) {
		SCOPED_TRACE(test.name);
		auto evt = generate_getcwd_failed_entry_event();
		auto tinfo = evt->get_thread_info();
		ASSERT_NE(tinfo, nullptr);
		const std::vector<std::string> args = {test.input};
		tinfo->set_args(args);
		std::string output;
		ASSERT_TRUE(formatter.tostring_withformat(evt, output, sinsp_evt_formatter::OF_JSON));
		Json::Value json;
		Json::Reader reader;
		ASSERT_TRUE(reader.parse(output, json)) << output;
		ASSERT_TRUE(json["proc.args"].isString());
		EXPECT_EQ(json["proc.args"].asString(), test.expected);
		// Formatting JSON must not alter normal output or the inspector's argument bytes.
		ASSERT_TRUE(formatter.tostring_withformat(evt, output, sinsp_evt_formatter::OF_NORMAL));
		EXPECT_EQ(output, test.input);
		EXPECT_EQ(tinfo->m_args, args);
	}
}

TEST_F(sinsp_formatter_test, json_utf8_string_list) {
	auto evt = generate_getcwd_failed_entry_event();
	auto tinfo = evt->get_thread_info();
	ASSERT_NE(tinfo, nullptr);
	const std::vector<std::string> args = {"-o", "a\x80z", "-o", "caf\xc3\xa9\n"};
	tinfo->set_args(args);
	// getopt emits a string list containing each option followed by its value.
	const std::string field = "getopt((proc.args[0],proc.args[1],proc.args[2],proc.args[3]),o:)";
	sinsp_evt_formatter formatter(
	        &m_inspector,
	        "%getopt((proc.args[0],proc.args[1],proc.args[2],proc.args[3]),\"o:\")",
	        m_filter_list);
	formatter.set_resolve_transformed_fields(true);
	std::string output;
	ASSERT_TRUE(formatter.tostring_withformat(evt, output, sinsp_evt_formatter::OF_JSON));
	Json::Value json;
	Json::Reader reader;
	ASSERT_TRUE(reader.parse(output, json)) << output;
	ASSERT_TRUE(json[field].isArray()) << output;
	ASSERT_EQ(json[field].size(), 4);
	EXPECT_EQ(json[field][0].asString(), "o");
	EXPECT_EQ(json[field][1].asString(), "a\xef\xbf\xbdz");
	EXPECT_EQ(json[field][2].asString(), "o");
	EXPECT_EQ(json[field][3].asString(), "caf\xc3\xa9\n");
	EXPECT_EQ(tinfo->m_args, args);
}

TEST_F(sinsp_formatter_test, json_utf8_preserves_value_types) {
	auto evt = generate_getcwd_failed_entry_event();
	auto tinfo = evt->get_thread_info();
	ASSERT_NE(tinfo, nullptr);
	tinfo->set_args(std::vector<std::string>{"a\x80z"});
	tinfo->m_exe_writable = true;
	sinsp_evt_formatter formatter(&m_inspector,
	                              "*%proc.args %thread.tid %proc.is_exe_writable %evt.asynctype",
	                              m_filter_list);
	std::string output;
	ASSERT_TRUE(formatter.tostring_withformat(evt, output, sinsp_evt_formatter::OF_JSON));
	Json::Value json;
	Json::Reader reader;
	ASSERT_TRUE(reader.parse(output, json)) << output;
	EXPECT_EQ(json["proc.args"].asString(), "a\xef\xbf\xbdz");
	ASSERT_TRUE(json["thread.tid"].isInt64());
	EXPECT_EQ(json["thread.tid"].asInt64(), INIT_TID);
	ASSERT_TRUE(json["proc.is_exe_writable"].isBool());
	EXPECT_TRUE(json["proc.is_exe_writable"].asBool());
	EXPECT_TRUE(json.isMember("evt.asynctype"));
	EXPECT_TRUE(json["evt.asynctype"].isNull());
}

TEST_F(sinsp_formatter_test, json_preserves_deltatime_behavior) {
	sinsp_evt_formatter formatter(&m_inspector,
	                              "%evt.deltatime %evt.deltatime.s %evt.deltatime.ns",
	                              m_filter_list);
	const uint64_t first_ts = increasing_ts();
	for(uint64_t offset : {0ULL, 1000000042ULL, 2000000084ULL}) {
		SCOPED_TRACE(offset);
		auto evt = add_event_advance_ts(first_ts + offset,
		                                INIT_TID,
		                                PPME_SYSCALL_GETCWD_X,
		                                2,
		                                int64_t{-1},
		                                "/test/dir");
		std::string output;
		ASSERT_TRUE(formatter.tostring_withformat(evt, output, sinsp_evt_formatter::OF_JSON));
		// Preserve the existing second extraction, which observes the same timestamp and returns 0.
		EXPECT_EQ(output, "{\"evt.deltatime\":0,\"evt.deltatime.ns\":0,\"evt.deltatime.s\":0}");
	}
}

TEST_F(sinsp_formatter_test, lenght_shorter) {
	format("start %2proc.name end");
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "start in end");
	EXPECT_EQ(m_last_field_values.size(), 1) << pretty_print(m_last_field_values);
	EXPECT_EQ(m_last_field_values["proc.name"], "init");
}

TEST_F(sinsp_formatter_test, lenght_shorter_json) {
	format("start %2proc.name end", sinsp_evt_formatter::output_format::OF_JSON);
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "{\"proc.name\":\"init\"}");
	EXPECT_EQ(m_last_field_values.size(), 1) << pretty_print(m_last_field_values);
	EXPECT_EQ(m_last_field_values["proc.name"], "init");
}

TEST_F(sinsp_formatter_test, lenght_larger) {
	format("start %10proc.name end");
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "start init       end");
	EXPECT_EQ(m_last_field_values.size(), 1) << pretty_print(m_last_field_values);
	EXPECT_EQ(m_last_field_values["proc.name"], "init");
}

TEST_F(sinsp_formatter_test, lenght_larger_json) {
	format("start %10proc.name end", sinsp_evt_formatter::output_format::OF_JSON);
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "{\"proc.name\":\"init\"}");
	EXPECT_EQ(m_last_field_values.size(), 1) << pretty_print(m_last_field_values);
	EXPECT_EQ(m_last_field_values["proc.name"], "init");
}

TEST_F(sinsp_formatter_test, multiple_fields) {
	format("start %proc.name %thread.tid end");
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "start init 1 end");
	EXPECT_EQ(m_last_field_values.size(), 2) << pretty_print(m_last_field_values);
	EXPECT_EQ(m_last_field_values["proc.name"], "init");
	EXPECT_EQ(m_last_field_values["thread.tid"], "1");
}

TEST_F(sinsp_formatter_test, multiple_fields_json) {
	format("start %proc.name %thread.tid end", sinsp_evt_formatter::output_format::OF_JSON);
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "{\"proc.name\":\"init\",\"thread.tid\":1}");
	EXPECT_EQ(m_last_field_values.size(), 2) << pretty_print(m_last_field_values);
	EXPECT_EQ(m_last_field_values["proc.name"], "init");
	EXPECT_EQ(m_last_field_values["thread.tid"], "1");
}

TEST_F(sinsp_formatter_test, multiple_fields_with_no_blank) {
	format("start%proc.nameand%thread.tidend");
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "startinitand1end");
	EXPECT_EQ(m_last_field_values.size(), 2) << pretty_print(m_last_field_values);
	EXPECT_EQ(m_last_field_values["proc.name"], "init");
	EXPECT_EQ(m_last_field_values["thread.tid"], "1");
}

TEST_F(sinsp_formatter_test, stop_on_null) {
	format("start %proc.name %evt.asynctype end");
	EXPECT_EQ(m_last_res, false);
	EXPECT_EQ(m_last_output, "start init ");
	EXPECT_EQ(m_last_field_values.size(), 1) << pretty_print(m_last_field_values);
	EXPECT_EQ(m_last_field_values["proc.name"], "init");
}

TEST_F(sinsp_formatter_test, stop_on_null_json) {
	format("start %proc.name %evt.asynctype end", sinsp_evt_formatter::output_format::OF_JSON);
	EXPECT_EQ(m_last_res, false);
	EXPECT_EQ(m_last_output, "{\"proc.name\":\"init\"}");
	EXPECT_EQ(m_last_field_values.size(), 1) << pretty_print(m_last_field_values);
	EXPECT_EQ(m_last_field_values["proc.name"], "init");
}

TEST_F(sinsp_formatter_test, continue_on_null) {
	format("*start %proc.name %evt.asynctype end");
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "start init <NA> end");
	EXPECT_EQ(m_last_field_values.size(), 2) << pretty_print(m_last_field_values);
	EXPECT_EQ(m_last_field_values["proc.name"], "init");
	EXPECT_EQ(m_last_field_values["evt.asynctype"], "<NA>");
}

TEST_F(sinsp_formatter_test, continue_on_null_json) {
	format("*start %proc.name %evt.asynctype end", sinsp_evt_formatter::output_format::OF_JSON);
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "{\"evt.asynctype\":null,\"proc.name\":\"init\"}");
	EXPECT_EQ(m_last_field_values.size(), 2) << pretty_print(m_last_field_values);
	EXPECT_EQ(m_last_field_values["proc.name"], "init");
	EXPECT_EQ(m_last_field_values["evt.asynctype"], "<NA>");
}

TEST_F(sinsp_formatter_test, no_fields) {
	format("start end");
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "start end");
	EXPECT_EQ(m_last_field_values.size(), 0) << pretty_print(m_last_field_values);
}

TEST_F(sinsp_formatter_test, no_fields_json) {
	format("start end", sinsp_evt_formatter::output_format::OF_JSON);
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "null");
	EXPECT_EQ(m_last_field_values.size(), 0) << pretty_print(m_last_field_values);
}

TEST_F(sinsp_formatter_test, field_with_args) {
	format("start %proc.aname[0] end");
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "start init end");
	EXPECT_EQ(m_last_field_values.size(), 1) << pretty_print(m_last_field_values);
	EXPECT_EQ(m_last_field_values["proc.aname[0]"], "init");
}

TEST_F(sinsp_formatter_test, field_with_args_json) {
	format("start %proc.aname[0] end", sinsp_evt_formatter::output_format::OF_JSON);
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "{\"proc.aname[0]\":\"init\"}");
	EXPECT_EQ(m_last_field_values.size(), 1) << pretty_print(m_last_field_values);
	EXPECT_EQ(m_last_field_values["proc.aname[0]"], "init");
}

TEST_F(sinsp_formatter_test, multiple_fields_with_args_no_blank) {
	format("start%proc.aname[0]and%proc.apid[0]end");
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "startinitand1end");
	EXPECT_EQ(m_last_field_values.size(), 2) << pretty_print(m_last_field_values);
	EXPECT_EQ(m_last_field_values["proc.aname[0]"], "init");
	EXPECT_EQ(m_last_field_values["proc.apid[0]"], "1");
}

TEST_F(sinsp_formatter_test, invalid_transformers) {
	ASSERT_THROW(format("start %some_transformer(proc.aname) end"), sinsp_exception);
	ASSERT_THROW(format("start %val(proc.aname) end"), sinsp_exception);
	ASSERT_THROW(format("start %(proc.aname) end"), sinsp_exception);
	ASSERT_THROW(format("start %toupper(proc.aname"), sinsp_exception);
	ASSERT_THROW(format("start %toupper(tolower)"), sinsp_exception);
	ASSERT_THROW(format("start %toupper(tolower(proc.aname"), sinsp_exception);
	ASSERT_THROW(format("start %toupper(tolower(proc.aname)"), sinsp_exception);
	ASSERT_THROW(format("start %toupper(val(proc.aname))"), sinsp_exception);
	ASSERT_THROW(format("start %toupper(val(proc.aname)"), sinsp_exception);
	ASSERT_THROW(format("start %touper("), sinsp_exception);
	ASSERT_THROW(format("start %("), sinsp_exception);
	ASSERT_THROW(format("start %toupper(evt.num) end"), sinsp_exception);  // wrong type

	// note: whitespaces are not allowed between transformers
	ASSERT_THROW(format("start %toupper (proc.name) end"), sinsp_exception);
	ASSERT_NO_THROW(format("start %toupper( proc.name) end"));
	ASSERT_NO_THROW(format("start %toupper(proc.name ) end"));
	ASSERT_NO_THROW(format("start %toupper( proc.name ) end"));
	ASSERT_NO_THROW(format("start %toupper( tolower(proc.name)) end"));
	ASSERT_NO_THROW(format("start %toupper( tolower( proc.name)) end"));
	ASSERT_NO_THROW(format("start %toupper( tolower( proc.name )) end"));
	ASSERT_NO_THROW(format("start %toupper( tolower( proc.name ) ) end"));
}

TEST_F(sinsp_formatter_test, field_with_transformer) {
	format("start %toupper(proc.name) end");
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "start INIT end");
	EXPECT_EQ(m_last_field_values.size(), 2) << pretty_print(m_last_field_values);
	EXPECT_EQ(m_last_field_values["proc.name"], "init");
	EXPECT_EQ(m_last_field_values["toupper(proc.name)"], "INIT");
}

TEST_F(sinsp_formatter_test, field_with_transformer_excluded) {
	auto of = sinsp_evt_formatter::output_format::OF_NORMAL;
	format("start %toupper(proc.name) end", of, false);
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "start INIT end");
	EXPECT_EQ(m_last_field_values.size(), 1) << pretty_print(m_last_field_values);
	EXPECT_EQ(m_last_field_values["proc.name"], "init");
}

TEST_F(sinsp_formatter_test, field_with_transformer_excluded_json) {
	auto of = sinsp_evt_formatter::output_format::OF_JSON;
	format("start %toupper(proc.name) end", of, false);
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "{\"proc.name\":\"init\"}");
	EXPECT_EQ(m_last_field_values.size(), 1) << pretty_print(m_last_field_values);
	EXPECT_EQ(m_last_field_values["proc.name"], "init");
}

TEST_F(sinsp_formatter_test, field_with_transformer_and_arg) {
	format("start %toupper(evt.arg[1]) end");
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "start /TEST/DIR end");
	EXPECT_EQ(m_last_field_values.size(), 2) << pretty_print(m_last_field_values);
	EXPECT_EQ(m_last_field_values["evt.arg[1]"], "/test/dir");
	EXPECT_EQ(m_last_field_values["toupper(evt.arg[1])"], "/TEST/DIR");
}

TEST_F(sinsp_formatter_test, field_with_nested_transformer) {
	format("start %tolower(toupper(proc.name)) end");
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "start init end");
	EXPECT_EQ(m_last_field_values.size(), 2) << pretty_print(m_last_field_values);
	EXPECT_EQ(m_last_field_values["proc.name"], "init");
	EXPECT_EQ(m_last_field_values["tolower(toupper(proc.name))"], "init");
}

TEST_F(sinsp_formatter_test, field_with_nested_transformer_and_arg) {
	format("start %tolower(toupper(evt.arg[1])) end");
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "start /test/dir end");
	EXPECT_EQ(m_last_field_values.size(), 2) << pretty_print(m_last_field_values);
	EXPECT_EQ(m_last_field_values["evt.arg[1]"], "/test/dir");
	EXPECT_EQ(m_last_field_values["tolower(toupper(evt.arg[1]))"], "/test/dir");
}

TEST_F(sinsp_formatter_test, multiple_fields_with_transformer) {
	format("start %toupper(proc.name) %toupper(evt.arg.path) end");
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "start INIT /TEST/DIR end");
	EXPECT_EQ(m_last_field_values.size(), 4) << pretty_print(m_last_field_values);
	EXPECT_EQ(m_last_field_values["proc.name"], "init");
	EXPECT_EQ(m_last_field_values["evt.arg.path"], "/test/dir");
	EXPECT_EQ(m_last_field_values["toupper(proc.name)"], "INIT");
	EXPECT_EQ(m_last_field_values["toupper(evt.arg.path)"], "/TEST/DIR");
}

TEST_F(sinsp_formatter_test, multiple_fields_with_transformer_json) {
	format("start %toupper(proc.name) %toupper(evt.arg.path) end",
	       sinsp_evt_formatter::output_format::OF_JSON);
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output,
	          "{\"evt.arg.path\":\"/test/dir\",\"proc.name\":\"init\",\"toupper(evt.arg.path)\":\"/"
	          "TEST/DIR\",\"toupper(proc.name)\":\"INIT\"}");
	EXPECT_EQ(m_last_field_values.size(), 4) << pretty_print(m_last_field_values);
	EXPECT_EQ(m_last_field_values["proc.name"], "init");
	EXPECT_EQ(m_last_field_values["evt.arg.path"], "/test/dir");
	EXPECT_EQ(m_last_field_values["toupper(proc.name)"], "INIT");
	EXPECT_EQ(m_last_field_values["toupper(evt.arg.path)"], "/TEST/DIR");
}

TEST_F(sinsp_formatter_test, multiple_fields_with_transformer_no_blank) {
	format("start%toupper(proc.name)and%toupper(evt.arg.path)end");
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "startINITand/TEST/DIRend");
	EXPECT_EQ(m_last_field_values.size(), 4) << pretty_print(m_last_field_values);
	EXPECT_EQ(m_last_field_values["proc.name"], "init");
	EXPECT_EQ(m_last_field_values["evt.arg.path"], "/test/dir");
	EXPECT_EQ(m_last_field_values["toupper(proc.name)"], "INIT");
	EXPECT_EQ(m_last_field_values["toupper(evt.arg.path)"], "/TEST/DIR");
}

TEST_F(sinsp_formatter_test, length_shorter_with_transformer) {
	format("start %2toupper(proc.name) end");
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "start IN end");
	EXPECT_EQ(m_last_field_values.size(), 2) << pretty_print(m_last_field_values);
	EXPECT_EQ(m_last_field_values["proc.name"], "init");
	EXPECT_EQ(m_last_field_values["toupper(proc.name)"], "INIT");
}

TEST_F(sinsp_formatter_test, length_larger_with_transformer) {
	format("start %10toupper(proc.name) end");
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "start INIT       end");
	EXPECT_EQ(m_last_field_values.size(), 2) << pretty_print(m_last_field_values);
	EXPECT_EQ(m_last_field_values["proc.name"], "init");
	EXPECT_EQ(m_last_field_values["toupper(proc.name)"], "INIT");
}

TEST_F(sinsp_formatter_test, join_transformer) {
	format("start %join(\"->\", (proc.name, evt.arg.path)) end");
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "start init->/test/dir end");
	EXPECT_EQ(m_last_field_values.size(), 3) << pretty_print(m_last_field_values);
	EXPECT_EQ(m_last_field_values["proc.name"], "init");
	EXPECT_EQ(m_last_field_values["join(->,(proc.name,evt.arg.path))"], "init->/test/dir");
}

TEST_F(sinsp_formatter_test, concat_transformer) {
	format("start %concat(proc.name, evt.arg.path) end");
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "start init/test/dir end");
	EXPECT_EQ(m_last_field_values.size(), 3) << pretty_print(m_last_field_values);
	EXPECT_EQ(m_last_field_values["proc.name"], "init");
	EXPECT_EQ(m_last_field_values["concat(proc.name,evt.arg.path)"], "init/test/dir");
}

TEST_F(sinsp_formatter_test, concat_with_outer_transformer) {
	format("start %toupper(concat(proc.name, evt.arg.path)) end");
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "start INIT/TEST/DIR end");
	EXPECT_EQ(m_last_field_values.size(), 3) << pretty_print(m_last_field_values);
	EXPECT_EQ(m_last_field_values["proc.name"], "init");
	EXPECT_EQ(m_last_field_values["toupper(concat(proc.name,evt.arg.path))"], "INIT/TEST/DIR");
}

TEST_F(sinsp_formatter_test, concat_with_inner_transformer) {
	format("start %concat(toupper(proc.name), evt.arg.path) end");
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "start INIT/test/dir end");
	EXPECT_EQ(m_last_field_values.size(), 4) << pretty_print(m_last_field_values);
	EXPECT_EQ(m_last_field_values["proc.name"], "init");
	EXPECT_EQ(m_last_field_values["evt.arg.path"], "/test/dir");
	EXPECT_EQ(m_last_field_values["toupper(proc.name)"], "INIT");
	EXPECT_EQ(m_last_field_values["concat(toupper(proc.name),evt.arg.path)"], "INIT/test/dir");
}

TEST_F(sinsp_formatter_test, join_with_inner_transformer) {
	format("start %join(\"->\", (toupper(proc.name), tolower(evt.arg.path))) end");
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "start INIT->/test/dir end");
	EXPECT_EQ(m_last_field_values.size(), 4) << pretty_print(m_last_field_values);
	EXPECT_EQ(m_last_field_values["proc.name"], "init");
	EXPECT_EQ(m_last_field_values["evt.arg.path"], "/test/dir");
	EXPECT_EQ(m_last_field_values["toupper(proc.name)"], "INIT");
	EXPECT_EQ(m_last_field_values["join(->,(toupper(proc.name),tolower(evt.arg.path)))"],
	          "INIT->/test/dir");
}

TEST_F(sinsp_formatter_test, nested_concat_and_join) {
	format("start %toupper(join(\"->\", (concat(proc.name, evt.arg.path), proc.name))) end");
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "start INIT/TEST/DIR->INIT end");
	EXPECT_EQ(m_last_field_values.size(), 4) << pretty_print(m_last_field_values);
	EXPECT_EQ(m_last_field_values["proc.name"], "init");
	EXPECT_EQ(m_last_field_values["evt.arg.path"], "/test/dir");
	EXPECT_EQ(m_last_field_values["concat(proc.name,evt.arg.path)"], "init/test/dir");
	EXPECT_EQ(m_last_field_values["toupper(join(->,(concat(proc.name,evt.arg.path),proc.name)))"],
	          "INIT/TEST/DIR->INIT");
}

// Tests for proc.a* fields without arguments in output (issue #2229).
// These verify that ancestor fields produce meaningful output when used
// without an explicit [index] argument.

TEST_F(sinsp_formatter_test, ancestor_fields_no_arg_no_ancestors) {
	// init (tid=1) has ptid=0 which doesn't exist, so no ancestors.
	// With '*' prefix to continue on null, we expect <NA>.
	format("*start %proc.aname end");
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "start <NA> end");
}

TEST_F(sinsp_formatter_test, ancestor_aname_no_arg) {
	// Create: init(1) <- bash(2) <- child(3) via clone events
	generate_clone_x_event(0,
	                       2,
	                       2,
	                       1,
	                       PPM_CL_CLONE_CHILD_CLEARTID,
	                       DEFAULT_VALUE,
	                       DEFAULT_VALUE,
	                       "bash");
	generate_clone_x_event(0,
	                       3,
	                       3,
	                       2,
	                       PPM_CL_CLONE_CHILD_CLEARTID,
	                       DEFAULT_VALUE,
	                       DEFAULT_VALUE,
	                       "child");
	format("*start %proc.aname end", sinsp_evt_formatter::output_format::OF_NORMAL, true, 3);
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "start bash init end");
}

TEST_F(sinsp_formatter_test, ancestor_aname_no_arg_middle_of_output) {
	// Regression test: proc.aname without arg in the middle of the output
	// string previously caused undefined behavior (issue #2229).
	generate_clone_x_event(0,
	                       2,
	                       2,
	                       1,
	                       PPM_CL_CLONE_CHILD_CLEARTID,
	                       DEFAULT_VALUE,
	                       DEFAULT_VALUE,
	                       "bash");
	generate_clone_x_event(0,
	                       3,
	                       3,
	                       2,
	                       PPM_CL_CLONE_CHILD_CLEARTID,
	                       DEFAULT_VALUE,
	                       DEFAULT_VALUE,
	                       "child");
	format("hello |%proc.name| |%proc.aname| end",
	       sinsp_evt_formatter::output_format::OF_NORMAL,
	       true,
	       3);
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "hello |child| |bash init| end");
}

TEST_F(sinsp_formatter_test, ancestor_aexe_no_arg) {
	generate_clone_x_event(0,
	                       2,
	                       2,
	                       1,
	                       PPM_CL_CLONE_CHILD_CLEARTID,
	                       DEFAULT_VALUE,
	                       DEFAULT_VALUE,
	                       "bash");
	generate_clone_x_event(0,
	                       3,
	                       3,
	                       2,
	                       PPM_CL_CLONE_CHILD_CLEARTID,
	                       DEFAULT_VALUE,
	                       DEFAULT_VALUE,
	                       "child");
	format("*%proc.aexe", sinsp_evt_formatter::output_format::OF_NORMAL, true, 3);
	EXPECT_EQ(m_last_res, true);
	// clone event sets exe to the clone's name for the child
	EXPECT_EQ(m_last_output, "bash /sbin/init");
}

TEST_F(sinsp_formatter_test, ancestor_aexepath_no_arg) {
	generate_clone_x_event(0,
	                       2,
	                       2,
	                       1,
	                       PPM_CL_CLONE_CHILD_CLEARTID,
	                       DEFAULT_VALUE,
	                       DEFAULT_VALUE,
	                       "bash");
	generate_clone_x_event(0,
	                       3,
	                       3,
	                       2,
	                       PPM_CL_CLONE_CHILD_CLEARTID,
	                       DEFAULT_VALUE,
	                       DEFAULT_VALUE,
	                       "child");
	// Use proc.aname instead since exepath depends on clone internals
	// and is harder to predict. Just verify it doesn't crash or return <NA>.
	format("*%proc.aexepath", sinsp_evt_formatter::output_format::OF_NORMAL, true, 3);
	EXPECT_EQ(m_last_res, true);
	EXPECT_FALSE(m_last_output.empty());
	EXPECT_NE(m_last_output, "<NA>");
}

TEST_F(sinsp_formatter_test, ancestor_acmdline_no_arg) {
	generate_clone_x_event(0,
	                       2,
	                       2,
	                       1,
	                       PPM_CL_CLONE_CHILD_CLEARTID,
	                       DEFAULT_VALUE,
	                       DEFAULT_VALUE,
	                       "bash");
	generate_clone_x_event(0,
	                       3,
	                       3,
	                       2,
	                       PPM_CL_CLONE_CHILD_CLEARTID,
	                       DEFAULT_VALUE,
	                       DEFAULT_VALUE,
	                       "child");
	format("*%proc.acmdline", sinsp_evt_formatter::output_format::OF_NORMAL, true, 3);
	EXPECT_EQ(m_last_res, true);
	// clone child has no args so cmdline=name; init has args
	EXPECT_EQ(m_last_output, "bash init context ls --format {{json .}}");
}

TEST_F(sinsp_formatter_test, ancestor_apid_no_arg_defaults_to_self) {
	// proc.apid without argument defaults to proc.apid[0] (current process pid)
	generate_clone_x_event(0,
	                       2,
	                       2,
	                       1,
	                       PPM_CL_CLONE_CHILD_CLEARTID,
	                       DEFAULT_VALUE,
	                       DEFAULT_VALUE,
	                       "bash");
	format("*%proc.apid", sinsp_evt_formatter::output_format::OF_NORMAL, true, 2);
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "2");
}

TEST_F(sinsp_formatter_test, ancestor_aname_with_arg_still_works) {
	// Regression: proc.aname[0] must still work as before
	format("start %proc.aname[0] end");
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "start init end");
}

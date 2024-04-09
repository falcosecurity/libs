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

#include <libsinsp/sinsp.h>
#include <libsinsp/eventformatter.h>

#include <gtest/gtest.h>

#include <sinsp_with_test_input.h>

#include <memory>
#include <vector>
#include <string>
#include <iostream>

static std::string pretty_print(const std::map<std::string,std::string>& in)
{
	std::string ret = "(";
	for (const auto& v : in)
	{
		ret.append(" {'").append(v.first)
			.append("','").append(v.second).append("'}");
	}
	return ret.append(" )");
}

class sinsp_formatter_test : public sinsp_with_test_input
{
public:
	void SetUp() override
	{
		sinsp_with_test_input::SetUp();
		add_default_init_thread();
		open_inspector();
	}

	void TearDown() override
	{
		m_last_res = false;
		m_last_output.clear();
		m_last_field_names.clear();
		m_last_field_values.clear();
	}

	void format(const std::string& fmt,
				sinsp_evt_formatter::output_format of = sinsp_evt_formatter::output_format::OF_NORMAL)
	{
		sinsp_evt_formatter f(&m_inspector, fmt, m_filter_list);
		auto evt = generate_getcwd_exit_event();
		f.get_field_names(m_last_field_names);
		auto r1 = f.resolve_tokens(evt, m_last_field_values);
		auto r2 = f.tostring_withformat(evt, m_last_output, of);
		m_last_res = r1 && r2;
	}

	bool m_last_res;
	std::string m_last_output;
	std::vector<std::string> m_last_field_names;
	std::map<std::string,std::string> m_last_field_values;

	sinsp_filter_check_list m_filter_list;
};

TEST_F(sinsp_formatter_test, field_names)
{
	format("this is a sample output %proc.name %fd.type %proc.pid");
	EXPECT_EQ(m_last_field_names.size(), 3);
	EXPECT_NE(find(m_last_field_names.begin(), m_last_field_names.end(), "proc.name"), m_last_field_names.end());
	EXPECT_NE(find(m_last_field_names.begin(), m_last_field_names.end(), "fd.type"), m_last_field_names.end());
	EXPECT_NE(find(m_last_field_names.begin(), m_last_field_names.end(), "proc.pid"), m_last_field_names.end());
}

TEST_F(sinsp_formatter_test, invalid_tokens)
{
	EXPECT_THROW(format("start %some.field end"), sinsp_exception);
	EXPECT_THROW(format("start %a end"), sinsp_exception);
	EXPECT_THROW(format("start % end"), sinsp_exception);
	EXPECT_THROW(format("start %proc.name %"), sinsp_exception);
}

TEST_F(sinsp_formatter_test, field)
{
	format("start %proc.name end");
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "start init end");
	EXPECT_EQ(m_last_field_values.size(), 1) << pretty_print(m_last_field_values);
	EXPECT_EQ(m_last_field_values["proc.name"], "init");
}

TEST_F(sinsp_formatter_test, field_json)
{
	format("start %proc.name end", sinsp_evt_formatter::output_format::OF_JSON);
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "{\"proc.name\":\"init\"}");
	EXPECT_EQ(m_last_field_values.size(), 1) << pretty_print(m_last_field_values);
	EXPECT_EQ(m_last_field_values["proc.name"], "init");
}

TEST_F(sinsp_formatter_test, lenght_shorter)
{
	format("start %2proc.name end");
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "start in end");
	EXPECT_EQ(m_last_field_values.size(), 1) << pretty_print(m_last_field_values);
	EXPECT_EQ(m_last_field_values["proc.name"], "init");
}

TEST_F(sinsp_formatter_test, lenght_shorter_json)
{
	format("start %2proc.name end", sinsp_evt_formatter::output_format::OF_JSON);
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "{\"proc.name\":\"init\"}");
	EXPECT_EQ(m_last_field_values.size(), 1) << pretty_print(m_last_field_values);
	EXPECT_EQ(m_last_field_values["proc.name"], "init");
}

TEST_F(sinsp_formatter_test, lenght_larger)
{
	format("start %10proc.name end");
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "start init       end");
	EXPECT_EQ(m_last_field_values.size(), 1) << pretty_print(m_last_field_values);
	EXPECT_EQ(m_last_field_values["proc.name"], "init");
}

TEST_F(sinsp_formatter_test, lenght_larger_json)
{
	format("start %10proc.name end", sinsp_evt_formatter::output_format::OF_JSON);
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "{\"proc.name\":\"init\"}");
	EXPECT_EQ(m_last_field_values.size(), 1) << pretty_print(m_last_field_values);
	EXPECT_EQ(m_last_field_values["proc.name"], "init");
}

TEST_F(sinsp_formatter_test, multiple_fields)
{
	format("start %proc.name %thread.tid end");
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "start init 1 end");
	EXPECT_EQ(m_last_field_values.size(), 2) << pretty_print(m_last_field_values);
	EXPECT_EQ(m_last_field_values["proc.name"], "init");
	EXPECT_EQ(m_last_field_values["thread.tid"], "1");
}

TEST_F(sinsp_formatter_test, multiple_fields_json)
{
	format("start %proc.name %thread.tid end", sinsp_evt_formatter::output_format::OF_JSON);
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "{\"proc.name\":\"init\",\"thread.tid\":1}");
	EXPECT_EQ(m_last_field_values.size(), 2) << pretty_print(m_last_field_values);
	EXPECT_EQ(m_last_field_values["proc.name"], "init");
	EXPECT_EQ(m_last_field_values["thread.tid"], "1");
}

TEST_F(sinsp_formatter_test, multiple_fields_with_no_blank)
{
	format("start%proc.nameand%thread.tidend");
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "startinitand1end");
	EXPECT_EQ(m_last_field_values.size(), 2) << pretty_print(m_last_field_values);
	EXPECT_EQ(m_last_field_values["proc.name"], "init");
	EXPECT_EQ(m_last_field_values["thread.tid"], "1");
}

TEST_F(sinsp_formatter_test, stop_on_null)
{
	format("start %proc.name %evt.asynctype end");
	EXPECT_EQ(m_last_res, false);
	EXPECT_EQ(m_last_output, "start init ");
	EXPECT_EQ(m_last_field_values.size(), 1) << pretty_print(m_last_field_values);
	EXPECT_EQ(m_last_field_values["proc.name"], "init");
}

TEST_F(sinsp_formatter_test, stop_on_null_json)
{
	format("start %proc.name %evt.asynctype end", sinsp_evt_formatter::output_format::OF_JSON);
	EXPECT_EQ(m_last_res, false);
	EXPECT_EQ(m_last_output, "{\"proc.name\":\"init\"}");
	EXPECT_EQ(m_last_field_values.size(), 1) << pretty_print(m_last_field_values);
	EXPECT_EQ(m_last_field_values["proc.name"], "init");
}

TEST_F(sinsp_formatter_test, continue_on_null)
{
	format("*start %proc.name %evt.asynctype end");
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "start init <NA> end");
	EXPECT_EQ(m_last_field_values.size(), 2) << pretty_print(m_last_field_values);
	EXPECT_EQ(m_last_field_values["proc.name"], "init");
	EXPECT_EQ(m_last_field_values["evt.asynctype"], "<NA>");
}

TEST_F(sinsp_formatter_test, continue_on_null_json)
{
	format("*start %proc.name %evt.asynctype end", sinsp_evt_formatter::output_format::OF_JSON);
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "{\"evt.asynctype\":null,\"proc.name\":\"init\"}");
	EXPECT_EQ(m_last_field_values.size(), 2) << pretty_print(m_last_field_values);
	EXPECT_EQ(m_last_field_values["proc.name"], "init");
	EXPECT_EQ(m_last_field_values["evt.asynctype"], "<NA>");
}

TEST_F(sinsp_formatter_test, no_fields)
{
	format("start end");
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "start end");
	EXPECT_EQ(m_last_field_values.size(), 0) << pretty_print(m_last_field_values);
}

TEST_F(sinsp_formatter_test, no_fields_json)
{
	format("start end", sinsp_evt_formatter::output_format::OF_JSON);
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "null");
	EXPECT_EQ(m_last_field_values.size(), 0) << pretty_print(m_last_field_values);
}

TEST_F(sinsp_formatter_test, field_with_args)
{
	format("start %proc.aname[0] end");
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "start init end");
	EXPECT_EQ(m_last_field_values.size(), 1) << pretty_print(m_last_field_values);
	EXPECT_EQ(m_last_field_values["proc.aname[0]"], "init");
}

TEST_F(sinsp_formatter_test, field_with_args_json)
{
	format("start %proc.aname[0] end", sinsp_evt_formatter::output_format::OF_JSON);
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "{\"proc.aname[0]\":\"init\"}");
	EXPECT_EQ(m_last_field_values.size(), 1) << pretty_print(m_last_field_values);
	EXPECT_EQ(m_last_field_values["proc.aname[0]"], "init");
}

TEST_F(sinsp_formatter_test, multiple_fields_with_args_no_blank)
{
	format("start%proc.aname[0]and%proc.apid[0]end");
	EXPECT_EQ(m_last_res, true);
	EXPECT_EQ(m_last_output, "startinitand1end");
	EXPECT_EQ(m_last_field_values.size(), 2) << pretty_print(m_last_field_values);
	EXPECT_EQ(m_last_field_values["proc.aname[0]"], "init");
	EXPECT_EQ(m_last_field_values["proc.apid[0]"], "1");
}

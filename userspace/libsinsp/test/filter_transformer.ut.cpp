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

#include <gtest/gtest.h>

#include <set>
#include <libsinsp/utils.h>
#include <libsinsp/sinsp_filter_transformer.h>
#include <sinsp_with_test_input.h>

static std::set<ppm_param_type> all_param_types() {
	std::set<ppm_param_type> ret;
	for(auto i = PT_NONE; i < PT_MAX; i = (ppm_param_type)((size_t)i + 1)) {
		ret.insert(i);
	}
	return ret;
}

static std::string supported_type_msg(ppm_param_type t, bool flags, bool support_expected) {
	return std::string("expected ") + (flags ? "list " : "") + "param type to" +
	       std::string((support_expected ? " " : " not ")) +
	       "be supported: " + std::string(param_type_to_string(t));
}

static std::string eq_test_msg(const std::pair<std::string, std::string> &tc) {
	return "expected '" + tc.first + "' (length: " + std::to_string(tc.first.length()) + ")" +
	       " to be equal to '" + tc.second + "' (length: " + std::to_string(tc.second.length()) +
	       ")";
}

static extract_value_t const_str_to_extract_value(const char *v) {
	extract_value_t ret;
	ret.ptr = (uint8_t *)v;
	ret.len = strlen(v) + 1;
	return ret;
}

template<class T>
static T extract_value_to_scalar(const extract_value_t &val) {
	T ret;
	EXPECT_EQ(val.len, sizeof(T));
	memcpy(&ret, val.ptr, val.len);
	return ret;
}

static void check_unsupported_types(sinsp_filter_transformer &tr,
                                    std::set<std::pair<ppm_param_type, bool>> &supported_types,
                                    std::vector<extract_value_t> sample_vals) {
	auto all_types = all_param_types();

	for(auto t : all_types) {
		uint32_t flags = EPF_IS_LIST;
		if(supported_types.find({t, flags}) == supported_types.end()) {
			auto vals = sample_vals;
			EXPECT_FALSE(tr.transform_type(t, flags)) << supported_type_msg(t, flags, false);
			EXPECT_ANY_THROW(tr.transform_values(vals, t, flags))
			        << supported_type_msg(t, flags, false);
		}

		flags = 0;
		if(supported_types.find({t, flags}) == supported_types.end()) {
			auto vals = sample_vals;
			EXPECT_FALSE(tr.transform_type(t, flags)) << supported_type_msg(t, flags, false);
			EXPECT_ANY_THROW(tr.transform_values(vals, t, flags))
			        << supported_type_msg(t, flags, false);
		}
	}
}

TEST(sinsp_filter_transformer, toupper) {
	sinsp_filter_transformer tr(filter_transformer_type::FTR_TOUPPER);

	auto all_types = all_param_types();

	auto supported_types = std::set<std::pair<ppm_param_type, bool>>(
	        {{PT_CHARBUF, false}, {PT_FSPATH, false}, {PT_FSRELPATH, false}});

	auto test_cases = std::vector<std::pair<std::string, std::string>>{
	        {"hello", "HELLO"},
	        {"world", "WORLD"},
	        {"eXcItED", "EXCITED"},
	        {"", ""},
	};

	std::vector<extract_value_t> sample_vals;

	for(auto &tc : test_cases) {
		sample_vals.push_back(const_str_to_extract_value(tc.first.c_str()));
	}

	check_unsupported_types(tr, supported_types, sample_vals);

	// check for supported types
	for(auto t : supported_types) {
		auto original_type = t.first;
		uint32_t flags = t.second ? EPF_IS_LIST : 0;
		auto transformed_type = original_type;
		EXPECT_TRUE(tr.transform_type(transformed_type, flags))
		        << supported_type_msg(original_type, t.second, true);
		EXPECT_EQ(original_type,
		          transformed_type);  // note: toupper is expected not to alter the type

		auto vals = sample_vals;
		EXPECT_TRUE(tr.transform_values(vals, transformed_type, flags))
		        << supported_type_msg(original_type, t.second, true);
		EXPECT_EQ(original_type, transformed_type);
		EXPECT_EQ(vals.size(), test_cases.size());

		for(uint32_t i = 0; i < test_cases.size(); i++) {
			EXPECT_EQ(std::string((const char *)vals[i].ptr), test_cases[i].second)
			        << eq_test_msg(test_cases[i]);
			EXPECT_EQ(vals[i].len, test_cases[i].second.length() + 1) << eq_test_msg(test_cases[i]);
		}
	}
}

TEST(sinsp_filter_transformer, tolower) {
	sinsp_filter_transformer tr(filter_transformer_type::FTR_TOLOWER);

	auto all_types = all_param_types();

	auto supported_types = std::set<std::pair<ppm_param_type, bool>>(
	        {{PT_CHARBUF, false}, {PT_FSPATH, false}, {PT_FSRELPATH, false}});

	auto test_cases = std::vector<std::pair<std::string, std::string>>{
	        {"HELLO", "hello"},
	        {"world", "world"},
	        {"NoT_eXcItED", "not_excited"},
	        {"", ""},
	};

	std::vector<extract_value_t> sample_vals;

	for(auto &tc : test_cases) {
		sample_vals.push_back(const_str_to_extract_value(tc.first.c_str()));
	}

	check_unsupported_types(tr, supported_types, sample_vals);

	// check for supported types
	for(auto t : supported_types) {
		auto original_type = t.first;
		uint32_t flags = t.second ? EPF_IS_LIST : 0;
		auto transformed_type = original_type;
		EXPECT_TRUE(tr.transform_type(transformed_type, flags))
		        << supported_type_msg(original_type, t.second, true);
		EXPECT_EQ(original_type,
		          transformed_type);  // note: tolower is expected not to alter the type

		auto vals = sample_vals;
		EXPECT_TRUE(tr.transform_values(vals, transformed_type, flags))
		        << supported_type_msg(original_type, t.second, true);
		EXPECT_EQ(original_type, transformed_type);
		EXPECT_EQ(vals.size(), test_cases.size());

		for(uint32_t i = 0; i < test_cases.size(); i++) {
			EXPECT_EQ(std::string((const char *)vals[i].ptr), test_cases[i].second)
			        << eq_test_msg(test_cases[i]);
			EXPECT_EQ(vals[i].len, test_cases[i].second.length() + 1) << eq_test_msg(test_cases[i]);
		}
	}
}

TEST(sinsp_filter_transformer, b64) {
	sinsp_filter_transformer tr(filter_transformer_type::FTR_BASE64);

	auto all_types = all_param_types();

	auto supported_types =
	        std::set<std::pair<ppm_param_type, bool>>({{PT_CHARBUF, false}, {PT_BYTEBUF, false}});

	auto test_cases = std::vector<std::pair<std::string, std::string>>{
	        {"aGVsbG8=", "hello"},
	        {"d29ybGQgIQ==", "world !"},
	        {"", ""},
	};

	std::vector<std::string> invalid_test_cases{"!!!"};

	std::vector<extract_value_t> sample_vals;
	for(auto &tc : test_cases) {
		sample_vals.push_back(const_str_to_extract_value(tc.first.c_str()));
	}

	check_unsupported_types(tr, supported_types, sample_vals);

	// check for supported types
	for(auto t : supported_types) {
		auto original_type = t.first;
		uint32_t flags = t.second ? EPF_IS_LIST : 0;
		auto transformed_type = original_type;
		EXPECT_TRUE(tr.transform_type(transformed_type, flags))
		        << supported_type_msg(original_type, t.second, true);
		EXPECT_EQ(original_type, transformed_type);  // note: b64 is expected not to alter the type

		auto vals = sample_vals;
		EXPECT_TRUE(tr.transform_values(vals, transformed_type, flags))
		        << supported_type_msg(original_type, t.second, true);
		EXPECT_EQ(original_type, transformed_type);
		EXPECT_EQ(vals.size(), test_cases.size());

		for(uint32_t i = 0; i < test_cases.size(); i++) {
			EXPECT_EQ(std::string((const char *)vals[i].ptr), test_cases[i].second)
			        << eq_test_msg(test_cases[i]);
			EXPECT_EQ(vals[i].len, test_cases[i].second.length() + 1) << eq_test_msg(test_cases[i]);
		}
	}

	std::vector<extract_value_t> invalid_vals;
	for(auto &tc : invalid_test_cases) {
		invalid_vals.push_back(const_str_to_extract_value(tc.c_str()));
	}

	// check invalid input being rejected
	{
		auto t = PT_CHARBUF;
		uint32_t flags = 0;
		EXPECT_FALSE(tr.transform_values(invalid_vals, t, flags));
		EXPECT_EQ(t, PT_CHARBUF);
	}
}

TEST(sinsp_filter_transformer, basename) {
	sinsp_filter_transformer tr(filter_transformer_type::FTR_BASENAME);

	auto all_types = all_param_types();

	auto supported_types = std::set<std::pair<ppm_param_type, bool>>(
	        {{PT_CHARBUF, false}, {PT_FSPATH, false}, {PT_FSRELPATH, false}});

	auto test_cases = std::vector<std::pair<std::string, std::string>>{
	        {"/home/ubuntu/hello.txt", "hello.txt"},
	        {"/usr/local/bin/cat", "cat"},
	        {"/", ""},
	        {"", ""},
	        {"/hello/", ""},
	        {"hello", "hello"},
	};

	std::vector<extract_value_t> sample_vals;

	for(auto &tc : test_cases) {
		sample_vals.push_back(const_str_to_extract_value(tc.first.c_str()));
	}

	check_unsupported_types(tr, supported_types, sample_vals);

	// check for supported types
	for(auto t : supported_types) {
		auto original_type = t.first;
		uint32_t flags = t.second ? EPF_IS_LIST : 0;
		auto transformed_type = original_type;
		EXPECT_TRUE(tr.transform_type(transformed_type, flags))
		        << supported_type_msg(original_type, t.second, true);
		EXPECT_EQ(original_type,
		          transformed_type);  // note: basename is expected not to alter the type

		auto vals = sample_vals;
		EXPECT_TRUE(tr.transform_values(vals, transformed_type, flags))
		        << supported_type_msg(original_type, t.second, true);
		EXPECT_EQ(original_type, transformed_type);
		EXPECT_EQ(vals.size(), test_cases.size());

		for(uint32_t i = 0; i < test_cases.size(); i++) {
			EXPECT_EQ(std::string((const char *)vals[i].ptr), test_cases[i].second)
			        << eq_test_msg(test_cases[i]);
			EXPECT_EQ(vals[i].len, test_cases[i].second.length() + 1) << eq_test_msg(test_cases[i]);
		}
	}
}

TEST(sinsp_filter_transformer, len_list) {
	sinsp_filter_transformer tr(filter_transformer_type::FTR_LEN);

	auto all_types = all_param_types();

	std::vector<std::string> list_values = {"value 1", "value 2", "value 3", "value 4"};
	std::vector<extract_value_t> list;

	for(auto &tc : list_values) {
		list.push_back(const_str_to_extract_value(tc.c_str()));
	}

	auto original_type = PT_CHARBUF;
	uint32_t original_flags = EPF_IS_LIST;
	auto type = original_type;
	auto flags = original_flags;
	EXPECT_TRUE(tr.transform_type(type, flags)) << supported_type_msg(original_type, true, true);
	EXPECT_EQ(type, PT_UINT64);
	EXPECT_EQ(flags & EPF_IS_LIST, 0);

	type = original_type;
	flags = original_flags;
	auto vals = list;
	EXPECT_TRUE(tr.transform_values(vals, type, flags))
	        << supported_type_msg(original_type, true, true);
	EXPECT_EQ(type, PT_UINT64);
	EXPECT_EQ(flags & EPF_IS_LIST, 0);
	ASSERT_EQ(vals.size(), 1);

	EXPECT_EQ(extract_value_to_scalar<uint64_t>(vals[0]), list_values.size());

	std::vector<extract_value_t> empty_list;
	type = original_type;
	flags = original_flags;
	vals = empty_list;
	EXPECT_TRUE(tr.transform_values(vals, type, flags))
	        << supported_type_msg(original_type, true, true);
	EXPECT_EQ(type, PT_UINT64);
	EXPECT_EQ(flags & EPF_IS_LIST, 0);
	ASSERT_EQ(vals.size(), 1);

	EXPECT_EQ(extract_value_to_scalar<uint64_t>(vals[0]), 0);
}

TEST_F(sinsp_with_test_input, basename_transformer) {
	add_default_init_thread();
	open_inspector();

	sinsp_evt *evt;

	int64_t dirfd = 3;
	const char *file_to_run = "/tmp/file_to_run";
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_E, 3, file_to_run, 0, 0);
	evt = add_event_advance_ts(increasing_ts(),
	                           1,
	                           PPME_SYSCALL_OPEN_X,
	                           6,
	                           dirfd,
	                           file_to_run,
	                           0,
	                           0,
	                           0,
	                           (uint64_t)0);

	EXPECT_TRUE(eval_filter(evt, "basename(fd.name) = file_to_run"));
	EXPECT_FALSE(eval_filter(evt, "basename(fd.name) = /tmp/file_to_run"));
}

TEST_F(sinsp_with_test_input, len_transformer) {
	add_default_init_thread();
	open_inspector();

	sinsp_evt *evt;

	int64_t dirfd = 3;
	const char *file_to_run = "/tmp/file_to_run";

	evt = add_event_advance_ts(increasing_ts(),
	                           1,
	                           PPME_SYSCALL_OPEN_X,
	                           6,
	                           dirfd,
	                           file_to_run,
	                           0,
	                           0,
	                           0,
	                           (uint64_t)0);

	// fd.types = (file)
	EXPECT_TRUE(eval_filter(evt, "len(fd.types) = 1"));
	EXPECT_TRUE(eval_filter(evt, "len(fd.types) > 0"));
	EXPECT_FALSE(eval_filter(evt, "len(fd.types) = 0"));

	EXPECT_TRUE(eval_filter(evt, "len(fd.name) = 16"));

	int64_t client_fd = 9;
	add_event_advance_ts(increasing_ts(),
	                     1,
	                     PPME_SOCKET_SOCKET_E,
	                     3,
	                     (uint32_t)PPM_AF_INET,
	                     (uint32_t)SOCK_STREAM,
	                     (uint32_t)0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_SOCKET_X, 1, client_fd);

	// fd.types = (ipv4,file)
	EXPECT_TRUE(eval_filter(evt, "len(fd.types) = 2"));
}

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

template<class T>
static T extract_value_to_scalar(const extract_value_t& val) {
	T ret;
	EXPECT_EQ(val.len, sizeof(T));
	memcpy(&ret, val.ptr, val.len);
	return ret;
}

static std::string supported_type_msg(ppm_param_type t, bool flags, bool support_expected) {
	return std::string("expected ") + (flags ? "list " : "") + "param type to" +
	       std::string((support_expected ? " " : " not ")) +
	       "be supported: " + std::string(param_type_to_string(t));
}

static std::string eq_test_msg(extract_value_t actual, extract_value_t expected) {
	return "expected '" + std::string(reinterpret_cast<const char*>(actual.ptr)) +
	       "' (length: " + std::to_string(actual.len) + ")" + " to be equal to '" +
	       std::string(reinterpret_cast<const char*>(expected.ptr)) +
	       "' (length: " + std::to_string(expected.len) + ")";
}

struct ex_value : public extract_value_t {
	ex_value(const ex_value& val) {
		m_storage = val.m_storage;
		len = val.len;

		ptr = (uint8_t*)m_storage.data();
	}

	ex_value(std::string val) {
		m_storage = std::vector<uint8_t>(val.c_str(), val.c_str() + val.size() + 1);

		len = m_storage.size();
		ptr = (uint8_t*)m_storage.data();
	}

	ex_value(uint64_t val) {
		uint8_t* bytes = reinterpret_cast<uint8_t*>(&val);
		m_storage = std::vector<uint8_t>(bytes, bytes + sizeof(uint64_t));

		len = sizeof(val);
		ptr = (uint8_t*)m_storage.data();
	}

	std::vector<uint8_t> m_storage;
};

struct test_case_entry {
	uint32_t flags;
	ppm_param_type input_type;
	std::vector<ex_value> input;
	ppm_param_type expected_type;
	std::vector<ex_value> expected;
};

static void check_unsupported_types(sinsp_filter_transformer& tr,
                                    std::set<ppm_param_type>& supported_types,
                                    std::set<ppm_param_type>& supported_list_types) {
	auto all_types = all_param_types();

	for(auto t : all_types) {
		uint32_t flags = EPF_IS_LIST;
		if(supported_list_types.find(t) == supported_list_types.end()) {
			EXPECT_FALSE(tr.transform_type(t, flags)) << supported_type_msg(t, flags, false);
			// vals is empty for simplicity, should not affect the test
			std::vector<extract_value_t> vals{};
			EXPECT_ANY_THROW(tr.transform_values(vals, t, flags))
			        << supported_type_msg(t, flags, false);
		}

		flags = 0;
		if(supported_types.find(t) == supported_types.end()) {
			EXPECT_FALSE(tr.transform_type(t, flags)) << supported_type_msg(t, flags, false);
			std::vector<extract_value_t> vals{};
			EXPECT_ANY_THROW(tr.transform_values(vals, t, flags))
			        << supported_type_msg(t, flags, false);
		}
	}
}

TEST(sinsp_filter_transformer, toupper) {
	sinsp_filter_transformer tr(filter_transformer_type::FTR_TOUPPER);

	std::set<ppm_param_type> supported_types{PT_CHARBUF, PT_FSPATH, PT_FSRELPATH};
	std::set<ppm_param_type> supported_list_types = supported_types;

	check_unsupported_types(tr, supported_types, supported_list_types);

	std::vector<test_case_entry> test_cases{
	        {0, PT_CHARBUF, {{"hello"}}, PT_CHARBUF, {{"HELLO"}}},
	        {0, PT_CHARBUF, {{"WORLD"}}, PT_CHARBUF, {{"WORLD"}}},
	        {0, PT_CHARBUF, {{"eXcItED"}}, PT_CHARBUF, {{"EXCITED"}}},
	        {0, PT_CHARBUF, {{""}}, PT_CHARBUF, {{""}}},
	        {0,
	         PT_CHARBUF,
	         {{"hello"}, {"wOrLd"}, {"ONE_1234"}},
	         PT_CHARBUF,
	         {{"HELLO"}, {"WORLD"}, {"ONE_1234"}}},
	};

	for(auto const& tc : test_cases) {
		auto transformed_type = tc.input_type;
		uint32_t flags = tc.flags;
		bool is_list = flags & EPF_IS_LIST;
		EXPECT_TRUE(tr.transform_type(transformed_type, flags))
		        << supported_type_msg(tc.input_type, is_list, true);
		EXPECT_EQ(transformed_type, tc.expected_type);

		std::vector<extract_value_t> vals{};
		for(auto const& val : tc.input) {
			vals.push_back(val);
		}

		transformed_type = tc.input_type;
		EXPECT_TRUE(tr.transform_values(vals, transformed_type, flags))
		        << supported_type_msg(tc.input_type, is_list, true);
		EXPECT_EQ(vals.size(), tc.expected.size());

		for(std::vector<extract_value_t>::size_type i = 0; i < vals.size(); i++) {
			std::string actual = (const char*)vals[i].ptr;
			std::string expected = (const char*)tc.expected[i].ptr;
			EXPECT_EQ(actual, expected) << eq_test_msg(vals[i], tc.expected[i]);
			EXPECT_EQ(vals[i].len, tc.expected[i].len) << eq_test_msg(vals[i], tc.expected[i]);
		}
	}
}

TEST(sinsp_filter_transformer, tolower) {
	sinsp_filter_transformer tr(filter_transformer_type::FTR_TOLOWER);

	std::set<ppm_param_type> supported_types{PT_CHARBUF, PT_FSPATH, PT_FSRELPATH};
	std::set<ppm_param_type> supported_list_types = supported_types;

	check_unsupported_types(tr, supported_types, supported_list_types);

	std::vector<test_case_entry> test_cases{
	        {0, PT_CHARBUF, {{"HELLO"}}, PT_CHARBUF, {{"hello"}}},
	        {0, PT_CHARBUF, {{"world"}}, PT_CHARBUF, {{"world"}}},
	        {0, PT_CHARBUF, {{"NoT eXcItED"}}, PT_CHARBUF, {{"not excited"}}},
	        {0, PT_CHARBUF, {{""}}, PT_CHARBUF, {{""}}},
	        {EPF_IS_LIST,
	         PT_CHARBUF,
	         {{"HELLO"}, {"wOrLd"}, {"one_1234"}},
	         PT_CHARBUF,
	         {{"hello"}, {"world"}, {"one_1234"}}},
	};

	for(auto const& tc : test_cases) {
		bool is_list = tc.flags & EPF_IS_LIST;
		uint32_t flags = tc.flags;
		auto transformed_type = tc.input_type;

		EXPECT_TRUE(tr.transform_type(transformed_type, flags))
		        << supported_type_msg(tc.input_type, is_list, true);
		EXPECT_EQ(transformed_type, tc.expected_type);

		std::vector<extract_value_t> vals{};
		for(auto const& val : tc.input) {
			vals.push_back(val);
		}

		transformed_type = tc.input_type;
		EXPECT_TRUE(tr.transform_values(vals, transformed_type, flags))
		        << supported_type_msg(tc.input_type, is_list, true);
		EXPECT_EQ(vals.size(), tc.expected.size());

		for(std::vector<extract_value_t>::size_type i = 0; i < vals.size(); i++) {
			std::string actual = (const char*)vals[i].ptr;
			std::string expected = (const char*)tc.expected[i].ptr;
			EXPECT_EQ(actual, expected) << eq_test_msg(vals[i], tc.expected[i]);
			EXPECT_EQ(vals[i].len, tc.expected[i].len) << eq_test_msg(vals[i], tc.expected[i]);
		}
	}
}

TEST(sinsp_filter_transformer, b64) {
	sinsp_filter_transformer tr(filter_transformer_type::FTR_BASE64);

	std::set<ppm_param_type> supported_types{PT_CHARBUF, PT_FSPATH, PT_FSRELPATH, PT_BYTEBUF};
	std::set<ppm_param_type> supported_list_types = supported_types;

	check_unsupported_types(tr, supported_types, supported_list_types);

	std::vector<test_case_entry> test_cases{
	        {0, PT_CHARBUF, {{"aGVsbG8="}}, PT_CHARBUF, {{"hello"}}},
	        {0, PT_CHARBUF, {{"d29ybGQgIQ=="}}, PT_CHARBUF, {{"world !"}}},
	        {0, PT_CHARBUF, {{""}}, PT_CHARBUF, {{""}}},
	};

	for(auto const& tc : test_cases) {
		bool is_list = tc.flags & EPF_IS_LIST;
		uint32_t flags = tc.flags;
		auto transformed_type = tc.input_type;

		EXPECT_TRUE(tr.transform_type(transformed_type, flags))
		        << supported_type_msg(tc.input_type, is_list, true);
		EXPECT_EQ(transformed_type, tc.expected_type);

		std::vector<extract_value_t> vals{};
		for(auto const& val : tc.input) {
			vals.push_back(val);
		}

		transformed_type = tc.input_type;
		EXPECT_TRUE(tr.transform_values(vals, transformed_type, flags))
		        << supported_type_msg(tc.input_type, is_list, true);
		EXPECT_EQ(vals.size(), tc.expected.size());

		for(std::vector<extract_value_t>::size_type i = 0; i < vals.size(); i++) {
			std::string actual = (const char*)vals[i].ptr;
			std::string expected = (const char*)tc.expected[i].ptr;
			EXPECT_EQ(actual, expected) << eq_test_msg(vals[i], tc.expected[i]);
			EXPECT_EQ(vals[i].len, tc.expected[i].len) << eq_test_msg(vals[i], tc.expected[i]);
		}
	}
}

TEST(sinsp_filter_transformer, basename) {
	sinsp_filter_transformer tr(filter_transformer_type::FTR_BASENAME);

	std::set<ppm_param_type> supported_types{PT_CHARBUF, PT_FSPATH, PT_FSRELPATH};
	std::set<ppm_param_type> supported_list_types = supported_types;

	check_unsupported_types(tr, supported_types, supported_list_types);

	std::vector<test_case_entry> test_cases{
	        {0, PT_CHARBUF, {{"/home/ubuntu/hello.txt"}}, PT_CHARBUF, {{"hello.txt"}}},
	        {0, PT_FSPATH, {{"/usr/local/bin/cat"}}, PT_FSPATH, {{"cat"}}},
	        {0, PT_FSPATH, {{"/"}}, PT_FSPATH, {{""}}},
	        {0, PT_CHARBUF, {{"/hello/"}}, PT_CHARBUF, {{""}}},
	        {0, PT_CHARBUF, {{"hello"}}, PT_CHARBUF, {{"hello"}}},
	        {0, PT_CHARBUF, {{""}}, PT_CHARBUF, {{""}}},
	};

	for(auto const& tc : test_cases) {
		bool is_list = tc.flags & EPF_IS_LIST;
		uint32_t flags = tc.flags;
		auto transformed_type = tc.input_type;

		EXPECT_TRUE(tr.transform_type(transformed_type, flags))
		        << supported_type_msg(tc.input_type, is_list, true);
		EXPECT_EQ(transformed_type, tc.expected_type);

		std::vector<extract_value_t> vals{};
		for(auto const& val : tc.input) {
			vals.push_back(val);
		}

		transformed_type = tc.input_type;
		EXPECT_TRUE(tr.transform_values(vals, transformed_type, flags))
		        << supported_type_msg(tc.input_type, is_list, true);
		EXPECT_EQ(vals.size(), tc.expected.size());

		for(std::vector<extract_value_t>::size_type i = 0; i < vals.size(); i++) {
			std::string actual = (const char*)vals[i].ptr;
			std::string expected = (const char*)tc.expected[i].ptr;
			EXPECT_EQ(actual, expected) << eq_test_msg(vals[i], tc.expected[i]);
			EXPECT_EQ(vals[i].len, tc.expected[i].len) << eq_test_msg(vals[i], tc.expected[i]);
		}
	}
}

TEST(sinsp_filter_transformer, len) {
	sinsp_filter_transformer tr(filter_transformer_type::FTR_LEN);

	std::set<ppm_param_type> supported_types{PT_CHARBUF, PT_FSPATH, PT_FSRELPATH, PT_BYTEBUF};
	std::set<ppm_param_type> supported_list_types = all_param_types();

	check_unsupported_types(tr, supported_types, supported_list_types);

	std::vector<test_case_entry> test_cases{
	        {0, PT_CHARBUF, {{"/home/ubuntu/hello.txt"}}, PT_UINT64, {{22}}},
	        {0, PT_FSPATH, {{"/"}}, PT_UINT64, {{1}}},
	        {EPF_IS_LIST, PT_FSPATH, {{"/hello"}}, PT_UINT64, {{1}}},
	        {EPF_IS_LIST, PT_CHARBUF, {}, PT_UINT64, {{0}}},
	        {EPF_IS_LIST, PT_UINT64, {{1}, {2}, {3}, {4}, {5}}, PT_UINT64, {{5}}},
	};

	for(auto const& tc : test_cases) {
		bool is_list = tc.flags & EPF_IS_LIST;
		uint32_t flags = tc.flags;
		auto transformed_type = tc.input_type;

		EXPECT_TRUE(tr.transform_type(transformed_type, flags))
		        << supported_type_msg(tc.input_type, is_list, true);
		EXPECT_EQ(transformed_type, tc.expected_type);

		std::vector<extract_value_t> vals{};
		for(auto const& val : tc.input) {
			vals.push_back(val);
		}

		transformed_type = tc.input_type;
		flags = tc.flags;
		EXPECT_TRUE(tr.transform_values(vals, transformed_type, flags))
		        << supported_type_msg(tc.input_type, is_list, true);
		EXPECT_EQ(vals.size(), tc.expected.size());

		for(std::vector<extract_value_t>::size_type i = 0; i < vals.size(); i++) {
			uint64_t actual = extract_value_to_scalar<uint64_t>(vals[i]);
			uint64_t expected = extract_value_to_scalar<uint64_t>(tc.expected[i]);
			EXPECT_EQ(actual, expected);
		}
	}
}

TEST_F(sinsp_with_test_input, basename_transformer) {
	add_default_init_thread();
	open_inspector();

	sinsp_evt* evt;

	int64_t dirfd = 3;
	const char* file_to_run = "/tmp/file_to_run";
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

	sinsp_evt* evt;

	int64_t dirfd = 3;
	const char* file_to_run = "/tmp/file_to_run";

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

	uint8_t read_buf[] = {'\x01', '\x02', '\x03', '\x04', '\x05', '\x06'};
	evt = add_event_advance_ts(increasing_ts(),
	                           1,
	                           PPME_SYSCALL_READ_X,
	                           4,
	                           (int64_t)0,
	                           scap_const_sized_buffer{read_buf, sizeof(read_buf)},
	                           (int64_t)0,
	                           (uint32_t)0);

	EXPECT_TRUE(eval_filter(evt, "len(evt.arg.data) == 6"));
}

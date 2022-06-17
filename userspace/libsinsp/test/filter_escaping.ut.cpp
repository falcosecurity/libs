/*
Copyright (C) 2022 The Falco Authors.

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

#include <filter/escaping.h>
#include <gtest/gtest.h>

using namespace libsinsp::filter;

class filter_escaping_test : public testing::Test
{
protected:
	void unidirectional(const std::string& in, const std::string& out)
	{
		ASSERT_STREQ(libsinsp::filter::escape_str(in).c_str(), out.c_str());
	}

	void bidirectional(const std::string& in)
	{
		ASSERT_STREQ(in.c_str(),
			     libsinsp::filter::unescape_str(libsinsp::filter::escape_str(in)).c_str());
	}
};

TEST_F(filter_escaping_test, spaces)
{
	std::string in = "some string";
	std::string out = "\"some string\"";

	unidirectional(in, out);
}

TEST_F(filter_escaping_test, spaces_bidirectional)
{
	std::string in = "some string";

	bidirectional(in);
}

TEST_F(filter_escaping_test, ws_chars)
{
	std::string in = "some\\b\\f\\n\\r\\tstring";
	std::string out = "\"some\\\\b\\\\f\\\\n\\\\r\\\\tstring\"";

	unidirectional(in, out);
}

TEST_F(filter_escaping_test, ws_chars_bidirectional)
{
	std::string in = "some\\b\\f\\n\\r\\tstring";

	bidirectional(in);
}

TEST_F(filter_escaping_test, double_quotes)
{
	std::string in = "some \"quoted string\"";
	std::string out = "\"some \\\"quoted string\\\"\"";

	unidirectional(in, out);
}

TEST_F(filter_escaping_test, double_quotes_bidirectional)
{
	std::string in = "some \"quoted string\"";

	bidirectional(in);
}

TEST_F(filter_escaping_test, single_quotes)
{
	std::string in = "some 'quoted string'";
	std::string out = "\"some 'quoted string'\"";

	unidirectional(in, out);
}

// Since this quoting is not truly reversible, this test simply
// ensures that the unescaping can be done, although it results in a
// different string than the original.

TEST_F(filter_escaping_test, single_quotes_bidirectional)
{
	std::string in = "some 'quoted string'";
	std::string out = "some 'quoted string'";

	ASSERT_STREQ(out.c_str(),
		     libsinsp::filter::unescape_str(libsinsp::filter::escape_str(in)).c_str());
}

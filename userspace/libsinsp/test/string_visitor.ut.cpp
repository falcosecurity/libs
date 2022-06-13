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

#include <filter/parser.h>
#include <gtest/gtest.h>

#include <memory>

using namespace std;
using namespace libsinsp::filter;
using namespace libsinsp::filter::ast;

class string_visitor_test : public testing::Test
{
protected:

	// In and out are different to test minor things like
	// consistent spacing between fields and values, top-level
	// parentheses, etc.
	void unidirectional(const std::string& in, const std::string& out)
	{
		parser parser(in);

		std::unique_ptr<ast::expr> e(parser.parse());

		ASSERT_STREQ(as_string(*(e.get())).c_str(), out.c_str());
	}

	void bidirectional(const std::string &filter)
	{
		std::unique_ptr<ast::expr> e1(parser(filter).parse());
		std::unique_ptr<ast::expr> e2(parser(as_string(*(e1.get()))).parse());
		ASSERT_TRUE(e1->is_equal(e2.get()));
	}

	std::string complex_filter =
		"("
		"	(evt.type = open or evt.type = openat)"
		"	and evt.is_open_write = true"
		"	and fd.typechar = f"
		"	and fd.num >= 0"
		")"
		"and ("
		"	fd.filename in ("
		"		.bashrc, .bash_profile, .bash_history, .bash_login,"
		"		.bash_logout, .inputrc, .profile, .cshrc, .login, .logout,"
		"		.history, .tcshrc, .cshdirs, .zshenv, .zprofile, .zshrc,"
		"		.zlogin, .zlogout"
		"	)"
		"	or fd.name in (/etc/profile, /etc/bashrc, /etc/csh.cshrc, /etc/csh.login)"
		"	or fd.directory in (/etc/zsh)"
		")"
		"and not proc.name in (ash, bash, csh, ksh, sh, tcsh, zsh, dash)"
		"and not ("
		"	proc.name = exe"
		"	and (proc.cmdline contains \"/var/lib/docker\" or proc.cmdline contains '/var/run/docker')"
		"	and proc.pname in (dockerd, docker, dockerd-current, docker-current)"
		")";

};

TEST_F(string_visitor_test, and_expr)
{
	std::string in = "proc.name=nginx and fd.name=/etc/passwd";
	std::string out = "(proc.name = nginx and fd.name = /etc/passwd)";

	unidirectional(in, out);
}

TEST_F(string_visitor_test, and_expr_bidirectional)
{
	std::string in = "proc.name=nginx and fd.name=/etc/passwd";

	bidirectional(in);
}

TEST_F(string_visitor_test, or_expr)
{
	std::string in = "proc.name=nginx or fd.name=/etc/passwd";
	std::string out = "(proc.name = nginx or fd.name = /etc/passwd)";

	unidirectional(in, out);
}

TEST_F(string_visitor_test, or_expr_bidirectional)
{
	std::string in = "proc.name=nginx or fd.name=/etc/passwd";

	bidirectional(in);
}

TEST_F(string_visitor_test, not_expr)
{
	std::string in = "not proc.name=nginx";
	std::string out = "not proc.name = nginx";

	unidirectional(in, out);
}

TEST_F(string_visitor_test, not_expr_bidirectional)
{
	std::string in = "not proc.name=nginx";

	bidirectional(in);
}

TEST_F(string_visitor_test, list_expr)
{
	std::string in = "proc.name in (nginx, apache)";

	unidirectional(in, in);
}

TEST_F(string_visitor_test, list_expr_bidirectional)
{
	std::string in = "proc.name in (nginx, apache)";

	bidirectional(in);
}

TEST_F(string_visitor_test, list_expr_escaped)
{
	std::string in = "proc.name in (\"some proc\", apache)";

	unidirectional(in, in);
}

TEST_F(string_visitor_test, list_expr_escaped_bidirectional)
{
	std::string in = "proc.name in (\"some proc\", apache)";

	bidirectional(in);
}

// No unidirectional version of this test--the single quoted string
// ends up being escaped with double quotes.
TEST_F(string_visitor_test, list_expr_escaped_bidirectional_single_quote)
{
	std::string in = "proc.name in ('some proc', apache)";

	bidirectional(in);
}

TEST_F(string_visitor_test, check_args)
{
	std::string in = "proc.aname[1] != nginx";

	unidirectional(in, in);
}

TEST_F(string_visitor_test, check_args_bidirectional)
{
	std::string in = "proc.aname[1] != nginx";

	bidirectional(in);
}

TEST_F(string_visitor_test, check_args_escaped)
{
	std::string in = "proc.aname[\"some proc\"] != nginx";

	unidirectional(in, in);
}

TEST_F(string_visitor_test, check_args_escaped_bidirectional)
{
	std::string in = "proc.aname[\"some proc\"] != nginx";

	bidirectional(in);
}

TEST_F(string_visitor_test, binary_check)
{
	std::string in = "proc.name=nginx";
	std::string out = "proc.name = nginx";

	unidirectional(in, out);
}

TEST_F(string_visitor_test, binary_check_bidirectional)
{
	std::string in = "proc.name=nginx";

	bidirectional(in);
}

TEST_F(string_visitor_test, binary_check_escaped)
{
	std::string in = "proc.name=\"some proc\"";
	std::string out = "proc.name = \"some proc\"";

	unidirectional(in, out);
}

TEST_F(string_visitor_test, binary_check_escaped_bidirectional)
{
	std::string in = "proc.name=\"some proc\"";

	bidirectional(in);
}

TEST_F(string_visitor_test, binary_check_escaped_single_quote)
{
	std::string in = "proc.name='some proc'";
	std::string out = "proc.name = \"some proc\"";

	unidirectional(in, out);
}

TEST_F(string_visitor_test, binary_check_escaped_nested_quotes)
{
	std::string in = "proc.name=\"some 'proc'\"";
	std::string out = "proc.name = \"some 'proc'\"";

	unidirectional(in, out);
}

TEST_F(string_visitor_test, unary_check)
{
	std::string in = "proc.name exists";

	unidirectional(in, in);
}

TEST_F(string_visitor_test, unary_check_bidirectional)
{
	std::string in = "proc.name exists";

	bidirectional(in);
}

TEST_F(string_visitor_test, unary_check_arg)
{
	std::string in = "proc.aname[1] exists";

	unidirectional(in, in);
}

TEST_F(string_visitor_test, unary_check_arg_bidirectional)
{
	std::string in = "proc.aname[1] exists";

	bidirectional(in);
}

TEST_F(string_visitor_test, unary_check_arg_escaped)
{
	std::string in = "proc.aname[\"some proc\"] exists";

	unidirectional(in, in);
}

TEST_F(string_visitor_test, unary_check_arg_escaped_bidirectional)
{
	std::string in = "proc.aname[\"some proc\"] exists";

	bidirectional(in);
}

TEST_F(string_visitor_test, macro_reference)
{
	std::string in = "(some_macro and proc.name = nginx)";

	unidirectional(in, in);
}

TEST_F(string_visitor_test, macro_reference_bidirectional)
{
	std::string in = "some_macro and proc.name = nginx";

	bidirectional(in);
}

TEST_F(string_visitor_test, complex)
{
	std::string out = "(((evt.type = open or evt.type = openat) and evt.is_open_write = true and fd.typechar = f and fd.num >= 0) and (fd.filename in (.bashrc, .bash_profile, .bash_history, .bash_login, .bash_logout, .inputrc, .profile, .cshrc, .login, .logout, .history, .tcshrc, .cshdirs, .zshenv, .zprofile, .zshrc, .zlogin, .zlogout) or fd.name in (/etc/profile, /etc/bashrc, /etc/csh.cshrc, /etc/csh.login) or fd.directory in (/etc/zsh)) and not proc.name in (ash, bash, csh, ksh, sh, tcsh, zsh, dash) and not (proc.name = exe and (proc.cmdline contains /var/lib/docker or proc.cmdline contains /var/run/docker) and proc.pname in (dockerd, docker, dockerd-current, docker-current)))";

	unidirectional(complex_filter, out);
}

TEST_F(string_visitor_test, complex_bidirectional)
{
	bidirectional(complex_filter);
}

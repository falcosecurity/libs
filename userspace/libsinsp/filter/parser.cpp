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

#include <cstring>
#include <iterator>
#include "escaping.h"
#include "parser.h"
#include "../utils.h"
#include "../sinsp_exception.h"

// todo: this is very gross, but we have to deal with this due to old
// compilers (e.g. GCC 4.8) not fully supporting C++ <regex>.
// By falling back to the POSIX regex format, we need to change some
// regex a little bit, but they are equivalent towards our grammar.
// This is mixed to the fact that we indirectly depend on Oniguruma
// due to the JQ dependency. When we bundle Oniguruma, we need to use
// its headers.
//
// We should definitely remove all this once we don't have to support
// older compilers anymore.
#ifndef _WIN32
	#ifdef USE_BUNDLED_ONIGURUMA
		#include <onigposix.h>
	#else
		#define USE_POSIX_REGEX
		#include <regex.h>
	#endif
#else   // _WIN32
	#include <regex>
#endif  // _WIN32

#ifdef USE_POSIX_REGEX
	#define RGX_NOTBLANK            "not[[:space:]]+"
	#define RGX_IDENTIFIER          "[a-zA-Z]+[a-zA-Z0-9_]*"
	#define RGX_FIELDNAME           "[a-zA-Z]+[a-zA-Z0-9_]*(\\.[a-zA-Z]+[a-zA-Z0-9_]*)+"
	#define RGX_FIELDARGBARESTR     "[^][\"'[:space:]]+"
	#define RGX_HEXNUM              "0[xX][0-9a-zA-Z]+"
	#define RGX_NUMBER              "[+\\-]?[0-9]+[\\.]?[0-9]*([eE][+\\-][0-9]+)?"
	#define RGX_BARESTR             "[^()\"'[:space:]=,]+"
#else   // USE_POSIX_REGEX
	#define RGX_NOTBLANK            "not[ \\b\\t\\n\\r]+"
	#define RGX_IDENTIFIER          "[a-zA-Z]+[a-zA-Z0-9_]*"
	#define RGX_FIELDNAME           "[a-zA-Z]+[a-zA-Z0-9_]*(\\.[a-zA-Z]+[a-zA-Z0-9_]*)+"
	#define RGX_FIELDARGBARESTR     "[^ \\b\\t\\n\\r\\[\\]\"']+"
	#define RGX_HEXNUM              "0[xX][0-9a-zA-Z]+"
	#define RGX_NUMBER              "[+\\-]?[0-9]+[\\.]?[0-9]*([eE][+\\-][0-9]+)?"
	#define RGX_BARESTR             "[^ \\b\\t\\n\\r\\(\\),=\"']+"
#endif  // USE_POSIX_REGEX

using namespace std;
using namespace libsinsp::filter;

static const vector<string> unary_ops =
{ 
	"exists"
};

static const vector<string> binary_num_ops = 
{ 
	"<=", "<", ">=", ">"
};

static const vector<string> binary_str_ops =
{
	"==", "=", "!=", "glob ", "contains ", "icontains ", "bcontains ",
	"startswith ", "bstartswith ", "endswith ",
};

static const vector<string> binary_list_ops =
{
	"intersects", "in", "pmatch"
};

static inline void update_pos(const char c, parser::pos_info& pos)
{
	pos.col++;
	if (c == '\r' || c == '\n')
	{
		pos.col = 1;
		pos.line++;
	}
	pos.idx++;
}

static void update_pos(const string& s, parser::pos_info& pos)
{
	for (const auto &c : s)
	{
		update_pos(c, pos);
	}
}

vector<string> parser::supported_operators(bool list_only)
{
	if (list_only)
	{
		return binary_list_ops;
	}
	vector<string> ops;
	ops.insert(ops.end(), unary_ops.begin(), unary_ops.end());
	ops.insert(ops.end(), binary_num_ops.begin(), binary_num_ops.end());
	ops.insert(ops.end(), binary_str_ops.begin(), binary_str_ops.end());
	ops.insert(ops.end(), binary_list_ops.begin(), binary_list_ops.end());
	transform(ops.begin(), ops.end(), ops.begin(), ::trim);
	return ops;
}

parser::parser(const string& input)
{
	m_input = input;
	m_pos.reset();
	m_depth = 0;
	m_max_depth = 100;
	m_parse_partial = false;
}

void parser::get_pos(pos_info& pos) const
{
	pos.idx = m_pos.idx;
	pos.col = m_pos.col;
	pos.line = m_pos.line;
}

parser::pos_info parser::get_pos() const
{
	pos_info info;
	get_pos(info);
	return info;
}

void parser::set_parse_partial(bool parse_partial)
{
	m_parse_partial = parse_partial;
}

void parser::set_max_depth(uint32_t max_depth)
{
	m_max_depth = max_depth;
}

ast::expr* parser::parse()
{
	if (m_input.size() == 0)
	{
		throw sinsp_exception("filter input string is empty");
	}
	m_pos.reset();
	m_last_token = "";
	m_depth = 0;
	auto res = parse_or();
	if (m_depth > 0)
	{
		ASSERT(false);
		throw sinsp_exception("parser recursion is unbalanced");
	}
	if (!m_parse_partial && m_pos.idx != m_input.size())
	{
		throw sinsp_exception("unexpected token after '" + m_last_token + "', expecting 'or', 'and'");
	}
	return res;
}

ast::expr* parser::parse_or()
{
	depth_push();
	ast::expr* child = nullptr;
	vector<ast::expr*> children;
	lex_blank();
	children.push_back(parse_and());
	lex_blank();
	while (lex_helper_str("or"))
	{
		if (!lex_blank())
		{
			if (lex_helper_str("("))
			{
				child = parse_embedded_remainder();
			}
			else
			{
				throw sinsp_exception("expected blank or '(' after 'or'");
			}
		}
		else
		{
			child = parse_and();
		}
		children.push_back(child);
		lex_blank();
	}
	depth_pop();
	if (children.size() > 1)
	{
		return new ast::or_expr(children);
	}
	return children[0];
}

ast::expr* parser::parse_and()
{
	depth_push();
	ast::expr* child = nullptr;
	vector<ast::expr*> children;
	lex_blank();
	children.push_back(parse_not());
	lex_blank();
	while (lex_helper_str("and"))
	{
		if (!lex_blank())
		{
			if (lex_helper_str("("))
			{
				child = parse_embedded_remainder();
			}
			else
			{
				throw sinsp_exception("expected blank or '(' after 'and'");
			}
		}
		else
		{
			child = parse_not();
		}
		children.push_back(child);
		lex_blank();
	}
	depth_pop();
	if (children.size() > 1)
	{
		return new ast::and_expr(children);
	}
	return children[0];
}

ast::expr* parser::parse_not()
{
	depth_push();
	bool is_not = false;
	ast::expr* child = nullptr;
	lex_blank();
	while (lex_helper_rgx(RGX_NOTBLANK))
	{
		is_not = !is_not;
	}
	if (lex_helper_str("not("))
	{
		is_not = !is_not;
		child = parse_embedded_remainder();
	}
	else
	{
		child = parse_check();
	}
	depth_pop();
	return is_not ? new ast::not_expr(child) : child;
}

// this is an internal helper to parse the remainder of a
// self-embedding expression right after having parsed a "("
ast::expr* parser::parse_embedded_remainder()
{
	depth_push();
	lex_blank();
	auto child = parse_or();
	lex_blank();
	if (!lex_helper_str(")"))
	{
		delete child;
		throw sinsp_exception("expected a ')' token");
	}
	depth_pop();
	return child;
}

ast::expr* parser::parse_check()
{
	depth_push();
	lex_blank();
	if (lex_helper_str("("))
	{
		auto child = parse_embedded_remainder();
		depth_pop();
		return child;
	}

	if (lex_field_name())
	{
		string field = m_last_token;
		string field_arg = "";
		if (lex_helper_str("["))
		{
			if (!lex_quoted_str() && !lex_field_arg_bare_str())
			{
				throw sinsp_exception("expected a valid field argument: a quoted string or a bare string");
			}
			field_arg = m_last_token;
			if (!lex_helper_str("]"))
			{
				throw sinsp_exception("expected a ']' token");
			}
		}

		lex_blank();
		if (lex_unary_op())
		{
			depth_pop();
			return new ast::unary_check_expr(field, field_arg, trim_str(m_last_token));
		}

		string op = "";
		ast::expr* value = NULL;
		lex_blank();
		if (lex_num_op())
		{
			op = m_last_token;
			value = parse_num_value();
		}
		else if (lex_str_op())
		{
			op = m_last_token;
			value = parse_str_value();
		}
		else if (lex_list_op())
		{
			op = m_last_token;
			value = parse_list_value();
		} 
		else
		{
			std::string ops = "";
			for (const auto &op : supported_operators())
			{
				ops += ops.empty() ? "" : ", ";
				ops += "'" + op + "'";
			}
			throw sinsp_exception("expected a valid check operator: one of " + ops);
		}
		depth_pop();
		return new ast::binary_check_expr(field, field_arg, trim_str(op), value);
	}

	if (lex_identifier())
	{
		depth_pop();
		return new ast::value_expr(m_last_token);
	}

	throw sinsp_exception("expected a '(' token, a field check, or an identifier");
}

ast::value_expr* parser::parse_num_value()
{
	depth_push();
	lex_blank();
	if (lex_hex_num() || lex_num())
	{
		depth_pop();
		return new ast::value_expr(m_last_token);
	}
	throw sinsp_exception("expected a number value");
}

ast::value_expr* parser::parse_str_value()
{
	depth_push();
	lex_blank();
	if (lex_quoted_str() || lex_bare_str())
	{
		depth_pop();
		return new ast::value_expr(m_last_token);
	}
	throw sinsp_exception("expected a string value");
}

ast::expr* parser::parse_list_value()
{
	depth_push();
	lex_blank();
	if (lex_helper_str("("))
	{
		bool should_be_empty = false;
		ast::value_expr* child = NULL;
		vector<string> values;

		lex_blank();
		try
		{
			child = parse_str_value();
		}
		catch(const sinsp_exception& e)
		{
			depth_pop();
			should_be_empty = true;
		}
		
		if (!should_be_empty)
		{
			values.push_back(child->value);
			delete child;
			lex_blank();
			while (lex_helper_str(","))
			{
				child = parse_str_value();
				values.push_back(child->value);
				delete child;
				lex_blank();
			}
		}

		if (!lex_helper_str(")"))
		{
			throw sinsp_exception("expected a ')' token");
		}
		depth_pop();
		return new ast::list_expr(values);
	}

	if (lex_identifier())
	{
		depth_pop();
		return new ast::value_expr(m_last_token);
	}

	throw sinsp_exception("expected a list or an identifier");
}

// note: lex_blank is the only lex method that does not update m_last_token.
bool parser::lex_blank()
{
	bool found = false;
	while(*cursor() == ' ' || *cursor() == '\t' || *cursor() == '\b'
			|| *cursor() == '\r' || *cursor() == '\n')
	{
		found = true;
		update_pos(*cursor(), m_pos);
	}
	return found;
}

inline bool parser::lex_identifier()
{
	return lex_helper_rgx(RGX_IDENTIFIER);
}

inline bool parser::lex_field_name()
{
	return lex_helper_rgx(RGX_FIELDNAME);
}

inline bool parser::lex_field_arg_bare_str()
{
	return lex_helper_rgx(RGX_FIELDARGBARESTR);
}

inline bool parser::lex_hex_num()
{
	return lex_helper_rgx(RGX_HEXNUM);
}

inline bool parser::lex_num()
{
	return lex_helper_rgx(RGX_NUMBER);
}

inline bool parser::lex_quoted_str()
{
	if (*cursor() == '\'' || *cursor() == '\"')
	{
		char prev = '\\';
		char delimiter = *cursor();
		pos_info pos = m_pos;
		m_last_token = "";
		while(*cursor() != '\0')
		{
			if (*cursor() == delimiter && prev != '\\')
			{
				update_pos(*cursor(), m_pos);
				m_last_token += delimiter;
				m_last_token = unescape_str(m_last_token);
				return true;
			}
			prev = *cursor();
			m_last_token += prev;
			update_pos(*cursor(), m_pos);
		}
		m_pos = pos;
	}
	return false;
}

inline bool parser::lex_bare_str()
{
	return lex_helper_rgx(RGX_BARESTR);
}

inline bool parser::lex_unary_op()
{
	return lex_helper_str_list(unary_ops);
}

inline bool parser::lex_num_op()
{
	return lex_helper_str_list(binary_num_ops);
}

inline bool parser::lex_str_op()
{
	return lex_helper_str_list(binary_str_ops);
}

inline bool parser::lex_list_op()
{
	return lex_helper_str_list(binary_list_ops);
}

bool parser::lex_helper_rgx(string rgx)
{
#ifndef _WIN32
	regex_t re;
	regmatch_t re_match;
	rgx = "^(" + rgx + ")";
    if (regcomp(&re, rgx.c_str(), REG_EXTENDED) != 0)
	{
        ASSERT(false);
		return false;
    }
    if (regexec(&re, cursor(), 1, &re_match, 0) == 0)
	{
		m_last_token = string(cursor(), re_match.rm_eo);
		update_pos(m_last_token, m_pos);
		regfree(&re);
		return true;
	}
	regfree(&re);
#else   // _WIN32
	cmatch match;
	auto r = regex("^(" + rgx + ")");
	if (regex_search (cursor(), match, r))
	{
		size_t group_idx = 0;
		if (match.size() > group_idx && match[group_idx].matched)
		{
			m_last_token = match[group_idx].str();
			update_pos(m_last_token, m_pos);
			return true;
		}
	}
#endif  // _WIN32

	return false;
}

bool parser::lex_helper_str(const string& str)
{
	if (strncmp(cursor(), str.c_str(), str.size()) == 0)
	{
		m_last_token = str;
		update_pos(m_last_token, m_pos);
		return true;
	}
	return false;
}

bool parser::lex_helper_str_list(const std::vector<std::string>& list)
{
	for (auto &op : list)
	{
		if (lex_helper_str(op))
		{
			return true;
		}
	}
	return false;
}

inline const char* parser::cursor()
{
	return m_input.c_str() + m_pos.idx;
}

inline string parser::trim_str(string str)
{
	trim(str);
	return str;
}

inline void parser::depth_push()
{
	m_depth++;
	if (m_depth >= m_max_depth)
	{
		throw sinsp_exception("exceeded max depth limit of " + to_string(m_max_depth));
	}
}

inline void parser::depth_pop()
{
	m_depth--;
}

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

#include <cstring>
#include <iterator>
#include <memory>
#include <libsinsp/filter/escaping.h>
#include <libsinsp/filter/parser.h>
#include <libsinsp/utils.h>
#include <libsinsp/sinsp_exception.h>


#include <re2/re2.h>

// these follow the POSIX standard
#define RGX_NOTBLANK            "(not[[:space:]]+)"
#define RGX_IDENTIFIER          "([a-zA-Z]+[a-zA-Z0-9_]*)"
#define RGX_FIELDNAME           "([a-zA-Z]+[a-zA-Z0-9_]*(\\.[a-zA-Z]+[a-zA-Z0-9_]*)+)"
#define RGX_FIELDARGBARESTR     "([^][\"'[:space:]]+)"
#define RGX_HEXNUM              "(0[xX][0-9a-zA-Z]+)"
#define RGX_NUMBER              "([+\\-]?[0-9]+[\\.]?[0-9]*([eE][+\\-][0-9]+)?)"
#define RGX_BARESTR             "([^()\"'[:space:]=,]+)"

// using pre-compiled regex for better performance
static re2::RE2 s_rgx_not_blank(RGX_NOTBLANK, re2::RE2::POSIX);
static re2::RE2 s_rgx_identifier(RGX_IDENTIFIER, re2::RE2::POSIX);
static re2::RE2 s_rgx_field_name(RGX_FIELDNAME, re2::RE2::POSIX);
static re2::RE2 s_rgx_field_arg_barestr(RGX_FIELDARGBARESTR, re2::RE2::POSIX);
static re2::RE2 s_rgx_hex_num(RGX_HEXNUM, re2::RE2::POSIX);
static re2::RE2 s_rgx_num(RGX_NUMBER, re2::RE2::POSIX);
static re2::RE2 s_rgx_barestr(RGX_BARESTR, re2::RE2::POSIX);

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
	"==", "=", "!=", "glob ", "iglob ", "contains ", "icontains ",
	"bcontains ", "startswith ", "bstartswith ", "endswith ",
};

static const vector<string> binary_list_ops =
{
	"intersects", "in", "pmatch"
};

static inline void update_pos(const char c, ast::pos_info& pos)
{
	pos.col++;
	if (c == '\r' || c == '\n')
	{
		pos.col = 1;
		pos.line++;
	}
	pos.idx++;
}

static void update_pos(const string& s, ast::pos_info& pos)
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

void parser::get_pos(ast::pos_info& pos) const
{
	pos.idx = m_pos.idx;
	pos.col = m_pos.col;
	pos.line = m_pos.line;
}

ast::pos_info parser::get_pos() const
{
	ast::pos_info info;
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

std::unique_ptr<ast::expr> parser::parse()
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

std::unique_ptr<ast::expr> parser::parse_or()
{
	auto pos = get_pos();

	depth_push();
	vector<std::unique_ptr<ast::expr>> children;
	lex_blank();
	children.push_back(parse_and());
	lex_blank();
	while (lex_helper_str("or"))
	{
		std::unique_ptr<ast::expr> child;
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
		children.push_back(std::move(child));
		lex_blank();
	}
	depth_pop();
	if (children.size() > 1)
	{
		return ast::or_expr::create(children, pos);
	}
	return std::move(children[0]);
}

std::unique_ptr<ast::expr> parser::parse_and()
{
	auto pos = get_pos();

	depth_push();
	std::unique_ptr<ast::expr> child;
	std::vector<std::unique_ptr<ast::expr>> children;
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
		children.push_back(std::move(child));
		lex_blank();
	}
	depth_pop();
	if (children.size() > 1)
	{
		return ast::and_expr::create(children, pos);
	}
	return std::move(children[0]);
}

std::unique_ptr<ast::expr> parser::parse_not()
{
	auto pos = get_pos();

	depth_push();
	bool is_not = false;
	std::unique_ptr<ast::expr> child;
	lex_blank();
	while (lex_helper_rgx(s_rgx_not_blank))
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
	return is_not ? ast::not_expr::create(std::move(child), pos) : std::move(child);
}

// this is an internal helper to parse the remainder of a
// self-embedding expression right after having parsed a "("
std::unique_ptr<ast::expr> parser::parse_embedded_remainder()
{
	depth_push();
	lex_blank();
	std::unique_ptr<ast::expr> child = parse_or();
	lex_blank();
	if (!lex_helper_str(")"))
	{
		throw sinsp_exception("expected a ')' token");
	}
	depth_pop();
	return child;
}

std::unique_ptr<ast::expr> parser::parse_check()
{
	auto pos = get_pos();

	depth_push();
	lex_blank();
	if (lex_helper_str("("))
	{
		std::unique_ptr<ast::expr> child = parse_embedded_remainder();
		depth_pop();
		return child;
	}

	if (lex_field_name())
	{
		return parse_check_field(pos);
	}

	if (lex_identifier())
	{
		depth_pop();
		return ast::value_expr::create(m_last_token, pos);
	}

	throw sinsp_exception("expected a '(' token, a field check, or an identifier");
}

std::unique_ptr<ast::expr> parser::parse_check_field(libsinsp::filter::ast::pos_info& pos)
{
	string field = m_last_token;
	string field_arg = "";

	if(lex_helper_str("["))
	{
		parse_check_field_arg(field_arg);
	}

	lex_blank();

	return parse_check_condition(field, field_arg, pos);
}


void parser::parse_check_field_arg(std::string& field_arg)
{
	if(!lex_quoted_str() && !lex_field_arg_bare_str())
	{
		throw sinsp_exception("expected a valid field argument: a quoted string or a bare string");
	}

	field_arg = m_last_token;

	if(!lex_helper_str("]"))
	{
		throw sinsp_exception("expected a ']' token");
	}
}

std::unique_ptr<ast::expr> parser::parse_check_condition(const std::string& field, const std::string& field_arg,
							 libsinsp::filter::ast::pos_info& pos)
{
	if(lex_unary_op())
	{
		depth_pop();
		return ast::unary_check_expr::create(field, field_arg, trim_str(m_last_token), pos);
	}

	string op = "";
	std::unique_ptr<ast::expr> value;

	lex_blank();

	if(lex_num_op())
	{
		op = m_last_token;
		value = parse_num_value();
	}
	else if(lex_str_op())
	{
		op = m_last_token;
		value = parse_str_value();
	}
	else if(lex_list_op())
	{
		op = m_last_token;
		value = parse_list_value();
	}
	else
	{
		std::string ops = "";
		for(const auto& op : supported_operators())
		{
			ops += ops.empty() ? "" : ", ";
			ops += "'" + op + "'";
		}
		throw sinsp_exception("expected a valid check operator: one of " + ops);
	}

	depth_pop();

	return ast::binary_check_expr::create(field, field_arg, trim_str(op), std::move(value), pos);
}

std::unique_ptr<ast::value_expr> parser::parse_num_value()
{
	depth_push();
	lex_blank();

	auto pos = get_pos();

	if (lex_hex_num() || lex_num())
	{
		depth_pop();
		return ast::value_expr::create(m_last_token, pos);
	}
	throw sinsp_exception("expected a number value");
}

std::unique_ptr<ast::value_expr> parser::parse_str_value()
{
	depth_push();
	lex_blank();

	auto pos = get_pos();

	if (lex_quoted_str() || lex_bare_str())
	{
		depth_pop();
		return ast::value_expr::create(m_last_token, pos);
	}
	throw sinsp_exception("expected a string value");
}

std::unique_ptr<ast::expr> parser::parse_list_value()
{
	depth_push();
	lex_blank();

	auto pos = get_pos();

	if (lex_helper_str("("))
	{
		bool should_be_empty = false;
		std::unique_ptr<ast::value_expr> child;
		std::vector<std::string> values;

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
			lex_blank();
			while (lex_helper_str(","))
			{
				child = parse_str_value();
				values.push_back(child->value);
				lex_blank();
			}
		}

		if (!lex_helper_str(")"))
		{
			throw sinsp_exception("expected a ')' token");
		}
		depth_pop();
		return ast::list_expr::create(values, pos);
	}

	if (lex_identifier())
	{
		depth_pop();
		return ast::value_expr::create(m_last_token, pos);
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
	return lex_helper_rgx(s_rgx_identifier);
}

inline bool parser::lex_field_name()
{
	return lex_helper_rgx(s_rgx_field_name);
}

inline bool parser::lex_field_arg_bare_str()
{
	return lex_helper_rgx(s_rgx_field_arg_barestr);
}

inline bool parser::lex_hex_num()
{
	return lex_helper_rgx(s_rgx_hex_num);
}

inline bool parser::lex_num()
{
	return lex_helper_rgx(s_rgx_num);
}

inline bool parser::lex_quoted_str()
{
	if (*cursor() == '\'' || *cursor() == '\"')
	{
		char prev = '\\';
		char delimiter = *cursor();
		ast::pos_info pos = m_pos;
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
	return lex_helper_rgx(s_rgx_barestr);
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

bool parser::lex_helper_rgx(const re2::RE2& rgx)
{
	ASSERT(rgx.ok());
	re2::StringPiece c(cursor(), m_input.size() - m_pos.idx);
	if (re2::RE2::Consume(&c, rgx, &m_last_token))
	{
		update_pos(m_last_token, m_pos);
		return true;
	}
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

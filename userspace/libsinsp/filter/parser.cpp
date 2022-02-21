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
#include <regex>
#include "parser.h"
#include "../utils.h"
#include "../sinsp_exception.h"

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
	"==", "=", "!=", "glob ", "contains ", "icontains ",
	"startswith ", "endswith ",
};

static const vector<string> binary_list_ops =
{
	"intersects", "in", "pmatch"
};

parser::parser(const string& input)
{
	m_input = input;
	m_pos.reset();
	m_depth = 0;
	m_max_depth = 100;
	m_parse_partial = false;
}

void parser::get_pos(pos_info& pos)
{
	pos.idx = m_pos.idx;
	pos.col = m_pos.col;
	pos.line = m_pos.line;
}

parser::pos_info parser::get_pos()
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
	vector<ast::expr*> children;
	lex_blank();
	children.push_back(parse_and());
	lex_blank();
	while (lex_helper_str("or"))
	{
		if (!lex_blank())
		{
			throw sinsp_exception("expected blank after 'or'");
		}
		children.push_back(parse_and());
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
	vector<ast::expr*> children;
	lex_blank();
	children.push_back(parse_not());
	lex_blank();
	while (lex_helper_str("and"))
	{
		if (!lex_blank())
		{
			throw sinsp_exception("expected blank after 'and'");
		}
		children.push_back(parse_not());
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
	lex_blank();
	while (lex_helper_str("not"))
	{
		if (!lex_blank())
		{
			throw sinsp_exception("expected blank after 'not'");
		}
		is_not = !is_not;
	}
	auto child = parse_check();
	lex_blank();
	depth_pop();
	if (is_not)
	{
		return new ast::not_expr(child);
	}
	return child;
}

ast::expr* parser::parse_check()
{
	depth_push();
	lex_blank();
	if (lex_helper_str("("))
	{
		lex_blank();
		auto child = parse_or();
		lex_blank();
		if (!lex_helper_str(")"))
		{
			delete child;
			throw sinsp_exception("expected a ')' token");
		}
		lex_blank();
		depth_pop();
		return child;
	}

	if (lex_field_name())
	{
		string field = m_last_token;
		string field_arg = "";
		if (lex_helper_str("["))
		{
			if (!lex_num() && !lex_quoted_str() && !lex_field_arg_bare_str())
			{
				throw sinsp_exception("expected a valid field argument: a number, quoted string, or a bare string");
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
			lex_blank();
			depth_pop();
			return new ast::unary_check_expr(field, field_arg, trim_str(m_last_token));
		}

		string op = "";
		ast::expr* value = NULL;
		if (lex_num_op())
		{
			lex_blank();
			op = m_last_token;
			value = parse_num_value();
		}
		else if (lex_str_op())
		{
			lex_blank();
			op = m_last_token;
			value = parse_str_value();
		}
		else if (lex_list_op())
		{
			lex_blank();
			op = m_last_token;
			value = parse_list_value();
		} 
		else
		{
			string ops = "";
			for (auto &o: unary_ops)
			{
				ops += "'" + trim_str(o) + "', ";
			}
			for (auto &o: binary_num_ops)
			{
				ops += "'" + trim_str(o) + "', ";
			}
			for (auto &o: binary_str_ops)
			{
				ops += "'" + trim_str(o) + "', ";
			}
			for (auto &o: binary_list_ops)
			{
				ops += "'" + trim_str(o) + "', ";
			}
			ops.erase(ops.size() - 2, 2);
			throw sinsp_exception("expected a valid check operator: one of " + ops);
		}
		depth_pop();
		return new ast::binary_check_expr(field, field_arg, trim_str(op), value);
	}

	if (lex_identifier())
	{
		lex_blank();
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
		lex_blank();
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
		lex_blank();
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
				lex_blank();
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
		lex_blank();
		depth_pop();
		return new ast::list_expr(values);
	}

	if (lex_identifier())
	{
		lex_blank();
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
		m_pos.col++;
		if (*cursor() == '\r' || *cursor() == '\n')
		{
			m_pos.col = 1;
			m_pos.line++;
		}
		m_pos.idx++;
	}
	return found;
}

inline bool parser::lex_identifier()
{
	return lex_helper_rgx("[a-zA-Z]+[a-zA-Z0-9_]*");
}

inline bool parser::lex_field_name()
{
	return lex_helper_rgx("[a-zA-Z]+[a-zA-Z0-9_]*(\\.[a-zA-Z]+[a-zA-Z0-9_]*)+");
}

inline bool parser::lex_field_arg_bare_str()
{
	return lex_helper_rgx("[^ \\b\\t\\n\\r\\[\\]\"']+");
}

inline bool parser::lex_hex_num()
{
	return lex_helper_rgx("0[xX][0-9a-zA-Z]+");
}

inline bool parser::lex_num()
{
	return lex_helper_rgx("[+\\-]?[0-9]+[\\.]?[0-9]*([eE][+\\-][0-9]+)?");
}

inline bool parser::lex_quoted_str()
{
	if(lex_helper_rgx("\"(?:\\\\\"|.)*?\"|'(?:\\\\'|.)*?'"))
	{
		m_last_token = escape_str(m_last_token);
		return true;
	}
	return false;
}

inline bool parser::lex_bare_str()
{
	return lex_helper_rgx("[^ \\b\\t\\n\\r\\(\\),=\"']+");
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
	cmatch match;
	auto r = regex("^(" + rgx + ")");
	if (regex_search (cursor(), match, r))
	{
		size_t group_idx = 0;
		if (match.size() > group_idx && match[group_idx].matched)
		{
			m_last_token = match[group_idx].str();
			m_pos.idx += m_last_token.size();
			m_pos.col += m_last_token.size();
			return true;
		}
	}
	return false;
}

bool parser::lex_helper_str(string str)
{
	if (strncmp(cursor(), str.c_str(), str.size()) == 0)
	{
		m_last_token = str;
		m_pos.idx += m_last_token.size();
		m_pos.col += m_last_token.size();
		return true;
	}
	return false;
}

bool parser::lex_helper_str_list(vector<string> list)
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

string parser::escape_str(string& str)
{
	string res = "";
	size_t len = str.size() - 1;
	bool escaped = false;
	for (size_t i = 1; i < len; i++)
	{
		if (!escaped)
		{
			if (str[i] == '\\')
			{
				escaped = true;
			}
			else 
			{
				res += str[i];
			}
		}
		else
		{
			switch(str[i])
			{
				case 'b':
					res += '\b';
					break;
				case 'f':
					res += '\f';
					break;
				case 'n':
					res += '\n';
					break;
				case 'r':
					res += '\r';
					break;
				case 't':
					res += '\t';
					break;
				case ' ':
					// NOTE: we may need to initially support this to not create breaking changes with
					// some existing wrongly-escaped rules. So far, I only found one, in Falco:
					// https://github.com/falcosecurity/falco/blob/204f9ff875be035e620ca1affdf374dd1c610a98/rules/falco_rules.yaml#L3046
					// todo(jasondellaluce): remove this once rules are rewritten with correct escaping
				case '\\':
					res += '\\';
					break;
				case '/':
					res += '/';
					break;
				case '"':
					if (str[0] != str[i]) 
					{
						throw sinsp_exception("invalid \\\" escape in '-quoted string");
					}
					res += '\"';
					break;
				case '\'':
					if (str[0] != str[i]) 
					{
						throw sinsp_exception("invalid \\' escape in \"-quoted string");
					}
					res += '\'';
					break;
				case 'x':
					// todo(jasondellaluce): support hex num escaping (not needed for now)
				default:
					throw sinsp_exception("unsupported string escape sequence: \\" + str[i]);
			}
			escaped = false;
		}
	}
	return res;
}

inline string parser::trim_str(const string& str)
{
	string val = str;
	trim(val);
	return val;
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

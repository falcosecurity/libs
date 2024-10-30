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
#include <memory>
#include <libsinsp/filter/escaping.h>
#include <libsinsp/filter/parser.h>
#include <libsinsp/utils.h>
#include <libsinsp/sinsp_exception.h>

#include <re2/re2.h>

// these follow the POSIX standard
#define RGX_NOTBLANK "(not[[:space:]]+)"
#define RGX_IDENTIFIER "([a-zA-Z]+[a-zA-Z0-9_]*)"
#define RGX_FIELDNAME "([a-zA-Z]+[a-zA-Z0-9_]*(\\.[a-zA-Z]+[a-zA-Z0-9_]*)+)"
#define RGX_FIELDARGBARESTR "([^][\"'[:space:]]+)"
#define RGX_HEXNUM "(0[xX][0-9a-fA-F]+)"
#define RGX_NUMBER "([+\\-]?[0-9]+[\\.]?[0-9]*([eE][+\\-][0-9]+)?)"
#define RGX_BARESTR "([^()\"'[:space:]=,]+)"

// small utility for monitoring the depth of parser's recursion
class depth_guard {
public:
	inline ~depth_guard() { m_val--; }

	inline depth_guard(uint32_t max, uint32_t& v): m_val(v) {
		m_val++;
		if(m_val >= max) {
			throw sinsp_exception("exceeded max depth limit of " + std::to_string(max));
		}
	}

private:
	uint32_t& m_val;
};

// using pre-compiled regex for better performance
static re2::RE2 s_rgx_not_blank(RGX_NOTBLANK, re2::RE2::POSIX);
static re2::RE2 s_rgx_identifier(RGX_IDENTIFIER, re2::RE2::POSIX);
static re2::RE2 s_rgx_field_name(RGX_FIELDNAME, re2::RE2::POSIX);
static re2::RE2 s_rgx_field_arg_barestr(RGX_FIELDARGBARESTR, re2::RE2::POSIX);
static re2::RE2 s_rgx_hex_num(RGX_HEXNUM, re2::RE2::POSIX);
static re2::RE2 s_rgx_num(RGX_NUMBER, re2::RE2::POSIX);
static re2::RE2 s_rgx_barestr(RGX_BARESTR, re2::RE2::POSIX);

using namespace libsinsp::filter;

static const std::vector<std::string> s_unary_ops = {"exists"};

static const std::vector<std::string> s_binary_num_ops = {"<=", "<", ">=", ">"};

// note: by convention, we put a space at the end of operators requiring
// a blank character after them (i.e. whitespace, line break, ...)
static const std::vector<std::string> s_binary_str_ops = {
        "==",
        "=",
        "!=",
        "glob ",
        "iglob ",
        "contains ",
        "icontains ",
        "bcontains ",
        "startswith ",
        "bstartswith ",
        "endswith ",
        "regex ",
};

static const std::vector<std::string> s_binary_list_ops = {
        "intersects",
        "in",
        "pmatch",
};

static constexpr const char* s_field_transformer_val = "val(";

static const std::vector<std::string> s_field_transformers =
        {"tolower(", "toupper(", "b64(", "basename(", "len(", "join("};

static inline void update_pos(const char c, ast::pos_info& pos) {
	pos.col++;
	if(c == '\r' || c == '\n') {
		pos.col = 1;
		pos.line++;
	}
	pos.idx++;
}

static void update_pos(const std::string& s, ast::pos_info& pos) {
	for(const auto& c : s) {
		update_pos(c, pos);
	}
}

template<typename T>
inline std::string token_list_to_str(const T& vals) {
	std::string ret;
	for(const auto& v : vals) {
		ret += ret.empty() ? "" : ", ";
		ret += "'" + v + "'";
	}
	return ret;
}

std::vector<std::string> parser::supported_operators(bool list_only) {
	if(list_only) {
		return s_binary_list_ops;
	}
	std::vector<std::string> ops;
	ops.insert(ops.end(), s_unary_ops.begin(), s_unary_ops.end());
	ops.insert(ops.end(), s_binary_num_ops.begin(), s_binary_num_ops.end());
	ops.insert(ops.end(), s_binary_str_ops.begin(), s_binary_str_ops.end());
	ops.insert(ops.end(), s_binary_list_ops.begin(), s_binary_list_ops.end());
	transform(ops.begin(), ops.end(), ops.begin(), ::trim);
	return ops;
}

std::vector<std::string> parser::supported_field_transformers(bool include_val) {
	std::vector<std::string> res;
	if(include_val) {
		res.push_back(s_field_transformer_val);
		res.back().pop_back();  // remove '(' char
	}
	for(const auto& v : s_field_transformers) {
		res.push_back(v);
		res.back().pop_back();  // remove '(' char
	}
	return res;
}

parser::parser(const std::string& input) {
	m_input = input;
	m_pos.reset();
	m_depth = 0;
	m_max_depth = 100;
	m_parse_partial = false;
}

void parser::get_pos(ast::pos_info& pos) const {
	pos.idx = m_pos.idx;
	pos.col = m_pos.col;
	pos.line = m_pos.line;
}

ast::pos_info parser::get_pos() const {
	ast::pos_info info;
	get_pos(info);
	return info;
}

void parser::set_parse_partial(bool parse_partial) {
	m_parse_partial = parse_partial;
}

void parser::set_max_depth(uint32_t max_depth) {
	m_max_depth = max_depth;
}

std::unique_ptr<ast::expr> parser::parse() {
	if(m_input.size() == 0) {
		throw sinsp_exception("filter input string is empty");
	}
	m_pos.reset();
	m_last_token = "";
	m_depth = 0;
	auto res = parse_or();
	if(m_depth > 0) {
		ASSERT(false);
		throw sinsp_exception("parser fatal error: recursion is unbalanced");
	}
	if(!m_parse_partial && m_pos.idx != m_input.size()) {
		throw sinsp_exception("unexpected token after '" + m_last_token +
		                      "', expecting 'or', 'and'");
	}

	return res;
}

std::unique_ptr<ast::expr> parser::parse_field_or_transformer() {
	depth_guard(m_max_depth, m_depth);
	auto pos = get_pos();

	if(lex_field_name()) {
		return parse_field_remainder(m_last_token, pos);
	}

	if(lex_field_transformer_type()) {
		lex_blank();
		m_last_token.pop_back();  // discard '(' character
		return parse_field_or_transformer_remainder(m_last_token, pos);
	}

	throw sinsp_exception("unexpected token after '" + m_last_token);
}

std::unique_ptr<ast::expr> parser::parse_or() {
	depth_guard(m_max_depth, m_depth);
	auto pos = get_pos();

	std::vector<std::unique_ptr<ast::expr>> children;
	lex_blank();
	children.push_back(parse_and());
	lex_blank();
	while(lex_helper_str("or")) {
		std::unique_ptr<ast::expr> child;
		if(!lex_blank()) {
			if(lex_helper_str("(")) {
				child = parse_embedded_remainder();
			} else {
				throw sinsp_exception("expected blank or '(' after 'or'");
			}
		} else {
			child = parse_and();
		}
		children.push_back(std::move(child));
		lex_blank();
	}
	if(children.size() > 1) {
		return ast::or_expr::create(children, pos);
	}
	return std::move(children[0]);
}

std::unique_ptr<ast::expr> parser::parse_and() {
	depth_guard(m_max_depth, m_depth);
	auto pos = get_pos();

	std::unique_ptr<ast::expr> child;
	std::vector<std::unique_ptr<ast::expr>> children;
	lex_blank();
	children.push_back(parse_not());
	lex_blank();
	while(lex_helper_str("and")) {
		if(!lex_blank()) {
			if(lex_helper_str("(")) {
				child = parse_embedded_remainder();
			} else {
				throw sinsp_exception("expected blank or '(' after 'and'");
			}
		} else {
			child = parse_not();
		}
		children.push_back(std::move(child));
		lex_blank();
	}
	if(children.size() > 1) {
		return ast::and_expr::create(children, pos);
	}
	return std::move(children[0]);
}

std::unique_ptr<ast::expr> parser::parse_not() {
	depth_guard(m_max_depth, m_depth);
	auto pos = get_pos();

	bool is_not = false;
	std::unique_ptr<ast::expr> child;
	lex_blank();
	while(lex_helper_rgx(s_rgx_not_blank)) {
		is_not = !is_not;
	}
	if(lex_helper_str("not(")) {
		is_not = !is_not;
		child = parse_embedded_remainder();
	} else {
		child = parse_check();
	}
	return is_not ? ast::not_expr::create(std::move(child), pos) : std::move(child);
}

// this is an internal helper to parse the remainder of a
// self-embedding expression right after having parsed a "("
std::unique_ptr<ast::expr> parser::parse_embedded_remainder() {
	depth_guard(m_max_depth, m_depth);

	lex_blank();
	std::unique_ptr<ast::expr> child = parse_or();
	lex_blank();
	if(!lex_helper_str(")")) {
		throw sinsp_exception("expected a ')' token");
	}
	return child;
}

std::unique_ptr<ast::expr> parser::parse_check() {
	depth_guard(m_max_depth, m_depth);
	auto pos = get_pos();

	lex_blank();
	if(lex_helper_str("(")) {
		return parse_embedded_remainder();
	}

	if(lex_field_name()) {
		auto left = parse_field_remainder(m_last_token, pos);
		return parse_condition(std::move(left), pos);
	}

	if(lex_field_transformer_type()) {
		lex_blank();
		m_last_token.pop_back();  // discard '(' character
		auto left = parse_field_or_transformer_remainder(m_last_token, pos);
		return parse_condition(std::move(left), pos);
	}

	if(lex_identifier()) {
		return ast::identifier_expr::create(m_last_token, pos);
	}

	throw sinsp_exception("expected a '(' token, a field check, or an identifier");
}

std::unique_ptr<ast::expr> parser::parse_field_remainder(std::string fieldname,
                                                         const ast::pos_info& pos) {
	depth_guard(m_max_depth, m_depth);

	auto field = std::make_unique<ast::field_expr>();
	field->field = fieldname;
	field->set_pos(pos);

	if(lex_helper_str("[")) {
		if(!lex_quoted_str() && !lex_field_arg_bare_str()) {
			throw sinsp_exception(
			        "expected a valid field argument: a quoted string or a bare string");
		}

		field->arg = m_last_token;

		if(!lex_helper_str("]")) {
			throw sinsp_exception("expected a ']' token");
		}
	}

	return field;
}

// FieldTransformerTail ::= FieldTransformerArg ( ',' FieldTransformerArg )* ')'
inline std::unique_ptr<ast::expr> parser::parse_field_or_transformer_remainder(
        std::string transformer,
        const ast::pos_info& pos) {
	depth_guard(m_max_depth, m_depth);

	lex_blank();

	std::vector<std::unique_ptr<ast::expr>> children;

	do {
		children.emplace_back(parse_field_transformer_arg(get_pos()));
		lex_blank();
	} while(lex_helper_str(","));

	if(children.size() == 0) {
		throw sinsp_exception("expected a field or a nested valid transformer: " +
		                      token_list_to_str(supported_field_transformers(true)));
	}

	lex_blank();
	if(!lex_helper_str(")")) {
		throw sinsp_exception("expected a ')' token closing the transformer");
	}
	return ast::field_transformer_expr::create(transformer, children, pos);
}

// FieldTransformerArg ::= FieldTransformer | Field | QuotedStr | NumValue | TransformerList
inline std::unique_ptr<ast::expr> parser::parse_field_transformer_arg(const ast::pos_info& pos) {
	depth_guard(m_max_depth, m_depth);

	lex_blank();

	if(lex_hex_num() || lex_num()) {  // NumValue
		return ast::value_expr::create(m_last_token, pos);
	}

	if(lex_quoted_str()) {  // QuotedStr
		return ast::value_expr::create(m_last_token, pos);
	}

	if(lex_helper_str("(")) {  // TransformerList
		return parse_transformer_list(pos);
	}

	if(lex_field_transformer_type()) {  // FieldTransformer
		m_last_token.pop_back();        // discard '(' character
		return parse_field_or_transformer_remainder(m_last_token, pos);
	}

	if(lex_field_name()) {  // Field
		return parse_field_remainder(m_last_token, pos);
	}

	throw sinsp_exception(
	        "expected field transformer argument: "
	        "field, transformer, quoted string, number, or transformer list");
}

// TransformerList ::= '(' ( TransformerListArg (',' TransformerListArg)* )? ')'
// Note: Called after '(' has been consumed
inline std::unique_ptr<ast::expr> parser::parse_transformer_list(const ast::pos_info& pos) {
	std::vector<std::unique_ptr<ast::expr>> children;

	lex_blank();

	// Check for empty list
	if(lex_helper_str(")")) {
		return ast::transformer_list_expr::create(children, pos);
	}

	// Parse first element
	children.emplace_back(parse_transformer_list_arg(pos));

	// Parse remaining comma-separated elements
	lex_blank();
	while(lex_helper_str(",")) {
		lex_blank();
		children.emplace_back(parse_transformer_list_arg(pos));
		lex_blank();
	}

	if(!lex_helper_str(")")) {
		throw sinsp_exception("expected ')'");
	}
	return ast::transformer_list_expr::create(children, pos);
}

// TransformerListArg ::= Field | FieldTransformer | QuotedStr | NumValue
inline std::unique_ptr<ast::expr> parser::parse_transformer_list_arg(const ast::pos_info& pos) {
	if(lex_field_name()) {  // Field
		return parse_field_remainder(m_last_token, pos);
	}
	if(lex_field_transformer_type()) {  // FieldTransformer
		lex_blank();
		m_last_token.pop_back();
		return parse_field_or_transformer_remainder(m_last_token, pos);
	}
	if(lex_quoted_str()) {  // QuotedStr
		return ast::value_expr::create(m_last_token, pos);
	}
	if(lex_hex_num() || lex_num()) {  // NumValue
		return ast::value_expr::create(m_last_token, pos);
	}
	throw sinsp_exception(
	        "expected transformer list argument: "
	        "field, transformer, quoted string, or number");
}

std::unique_ptr<ast::expr> parser::parse_condition(std::unique_ptr<ast::expr> left,
                                                   const ast::pos_info& pos) {
	depth_guard(m_max_depth, m_depth);

	lex_blank();
	if(lex_unary_op()) {
		return ast::unary_check_expr::create(std::move(left), trim_str(m_last_token), pos);
	}

	std::string op = "";
	std::unique_ptr<ast::expr> right;

	lex_blank();

	if(lex_num_op()) {
		op = m_last_token;
		right = parse_num_value_or_transformer();
	} else if(lex_str_op()) {
		op = m_last_token;
		right = parse_str_value_or_transformer(false);
	} else if(lex_list_op()) {
		op = m_last_token;
		right = parse_list_value_or_transformer();
	} else {
		throw sinsp_exception("expected a valid check operator: one of " +
		                      token_list_to_str(supported_operators()));
	}

	return ast::binary_check_expr::create(std::move(left), trim_str(op), std::move(right), pos);
}

std::unique_ptr<ast::expr> parser::parse_num_value_or_transformer() {
	depth_guard(m_max_depth, m_depth);

	lex_blank();

	auto pos = get_pos();

	if(auto res = try_parse_transformer_or_val(); res != nullptr) {
		return res;
	}

	if(lex_hex_num() || lex_num()) {
		return ast::value_expr::create(m_last_token, pos);
	}

	throw sinsp_exception("expected a number value or a field with a valid transformer: " +
	                      token_list_to_str(supported_field_transformers(true)));
}

std::unique_ptr<ast::expr> parser::parse_str_value_or_transformer(bool no_transformer) {
	depth_guard(m_max_depth, m_depth);

	lex_blank();

	auto pos = get_pos();

	if(!no_transformer) {
		if(auto res = try_parse_transformer_or_val(); res != nullptr) {
			return res;
		}
	}

	if(lex_quoted_str() || lex_bare_str()) {
		return ast::value_expr::create(m_last_token, pos);
	}

	if(no_transformer) {
		throw sinsp_exception("expected a string value");
	}
	throw sinsp_exception("expected a string value or a field with a valid transformer: " +
	                      token_list_to_str(supported_field_transformers(true)));
}

std::unique_ptr<ast::expr> parser::parse_list_value_or_transformer() {
	depth_guard(m_max_depth, m_depth);

	lex_blank();

	auto pos = get_pos();

	if(lex_helper_str("(")) {
		bool should_be_empty = false;
		ast::value_expr* value_child = nullptr;
		std::unique_ptr<ast::expr> child;
		std::vector<std::string> values;

		lex_blank();
		try {
			child = parse_str_value_or_transformer(true);
		} catch(const sinsp_exception& e) {
			should_be_empty = true;
		}

		if(!should_be_empty) {
			value_child = dynamic_cast<ast::value_expr*>(child.get());
			if(!value_child) {
				throw sinsp_exception("parser fatal error: null value expr in head of list");
			}
			values.push_back(value_child->value);
			lex_blank();
			while(lex_helper_str(",")) {
				child = parse_str_value_or_transformer(true);
				value_child = dynamic_cast<ast::value_expr*>(child.get());
				if(!value_child) {
					throw sinsp_exception("parser fatal error: null value expr in body of list");
				}
				values.push_back(value_child->value);
				lex_blank();
			}
		}

		if(!lex_helper_str(")")) {
			throw sinsp_exception("expected a ')' token");
		}
		return ast::list_expr::create(values, pos);
	}

	if(auto res = try_parse_transformer_or_val(); res != nullptr) {
		return res;
	}

	if(lex_identifier()) {
		return ast::value_expr::create(m_last_token, pos);
	}

	throw sinsp_exception("expected a list, an identifier, or a field with a valid transformer: " +
	                      token_list_to_str(supported_field_transformers(true)));
}

// note: can return nullptr
std::unique_ptr<ast::expr> parser::try_parse_transformer_or_val() {
	depth_guard(m_max_depth, m_depth);

	lex_blank();

	auto pos = get_pos();

	if(lex_field_transformer_val()) {
		lex_blank();

		m_last_token.pop_back();  // discard '(' character;
		auto transformer = m_last_token;
		auto field_pos = get_pos();

		if(!lex_field_name()) {
			throw sinsp_exception("expected a field within '" + transformer + "' transformer");
		}
		std::vector<std::unique_ptr<ast::expr>> children;
		auto child = parse_field_remainder(m_last_token, field_pos);
		children.push_back(std::move(child));

		lex_blank();
		if(!lex_helper_str(")")) {
			throw sinsp_exception("expected a ')' token closing the transformer");
		}
		return ast::field_transformer_expr::create(transformer, children, pos);
	}

	if(lex_field_transformer_type()) {
		lex_blank();
		m_last_token.pop_back();  // discard '(' character
		return parse_field_or_transformer_remainder(m_last_token, pos);
	}

	return nullptr;
}

// note: lex_blank is the only lex method that does not update m_last_token.
bool parser::lex_blank() {
	bool found = false;
	while(*cursor() == ' ' || *cursor() == '\t' || *cursor() == '\b' || *cursor() == '\r' ||
	      *cursor() == '\n') {
		found = true;
		update_pos(*cursor(), m_pos);
	}
	return found;
}

inline bool parser::lex_identifier() {
	return lex_helper_rgx(s_rgx_identifier);
}

inline bool parser::lex_field_name() {
	return lex_helper_rgx(s_rgx_field_name);
}

inline bool parser::lex_field_arg_bare_str() {
	return lex_helper_rgx(s_rgx_field_arg_barestr);
}

inline bool parser::lex_hex_num() {
	return lex_helper_rgx(s_rgx_hex_num);
}

inline bool parser::lex_num() {
	return lex_helper_rgx(s_rgx_num);
}

inline bool parser::lex_quoted_str() {
	if(*cursor() == '\'' || *cursor() == '\"') {
		char prev = '\\';
		char delimiter = *cursor();
		ast::pos_info pos = m_pos;
		m_last_token = "";
		while(*cursor() != '\0') {
			if(*cursor() == delimiter && prev != '\\') {
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

inline bool parser::lex_bare_str() {
	return lex_helper_rgx(s_rgx_barestr);
}

inline bool parser::lex_unary_op() {
	return lex_helper_operator_list(s_unary_ops);
}

inline bool parser::lex_num_op() {
	return lex_helper_operator_list(s_binary_num_ops);
}

inline bool parser::lex_str_op() {
	return lex_helper_operator_list(s_binary_str_ops);
}

inline bool parser::lex_list_op() {
	return lex_helper_operator_list(s_binary_list_ops);
}

inline bool parser::lex_field_transformer_val() {
	return lex_helper_str(s_field_transformer_val);
}

inline bool parser::lex_field_transformer_type() {
	return lex_helper_str_list(s_field_transformers);
}

bool parser::lex_helper_rgx(const re2::RE2& rgx) {
	ASSERT(rgx.ok());
	re2::StringPiece c(cursor(), m_input.size() - m_pos.idx);
	if(re2::RE2::Consume(&c, rgx, &m_last_token)) {
		update_pos(m_last_token, m_pos);
		return true;
	}
	return false;
}

bool parser::lex_helper_str(const std::string& str) {
	if(strncmp(cursor(), str.c_str(), str.size()) == 0) {
		m_last_token = str;
		update_pos(m_last_token, m_pos);
		return true;
	}
	return false;
}

bool parser::lex_helper_str_list(const std::vector<std::string>& list) {
	for(auto& op : list) {
		if(lex_helper_str(op)) {
			return true;
		}
	}
	return false;
}

bool parser::lex_helper_operator_list(const std::vector<std::string>& list) {
	for(auto& op : list) {
		// if there's no ending whitespace, just parse the operator as-is
		if(op.back() != ' ') {
			if(lex_helper_str(op)) {
				return true;
			}
			continue;
		}

		// if there's an ending whitespace, we need to make sure there's
		// a blank after the operator (as long as we have an operator lexer match)
		if(lex_helper_str(trim_str(op))) {
			return lex_blank();
		}
	}
	return false;
}

inline const char* parser::cursor() {
	return m_input.c_str() + m_pos.idx;
}

inline std::string parser::trim_str(std::string str) {
	trim(str);
	return str;
}

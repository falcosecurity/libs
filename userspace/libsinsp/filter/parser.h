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

#pragma once

#include <libsinsp/filter/ast.h>
#include <cstdint>

namespace re2 {
class RE2;
};

//
// Context-free Grammar for Sinsp Filters
//
// Productions (EBNF Syntax):
//     Expr                ::= OrExpr
//     OrExpr              ::= AndExpr ('or' OrExprTail)*
//     OrExprTail          ::= ' ' AndExpr
//                             | '(' Expr ')'
//     AndExpr             ::= NotExpr ('and' AndExprTail)*
//     AndExprTail         ::= ' ' NotExpr
//                             | '(' Expr ')'
//     NotExpr             ::= ('not ')* NotExprTail
//     NotExprTail         ::= 'not(' Expr ')'
//                             | Check
//     Check               ::= Field Condition
//                             | FieldTransformer Condition
//                             | Identifier
//                             | '(' Expr ')'
//     FieldTransformer       ::= FieldTransformerType FieldTransformerTail
//     FieldTransformerTail   ::= FieldTransformerArg ')'
//     FieldTransformerArg    ::= FieldTransformer
//                             | Field
//     FieldTransformerOrVal  ::= FieldTransformer
//                             | FieldTransformerVal Field ')'
//     Condition           ::= UnaryOperator
//                             | NumOperator (NumValue | FieldTransformerOrVal)
//                             | StrOperator (StrValue | FieldTransformerOrVal)
//                             | ListOperator (ListValue | FieldTransformerOrVal)
//     ListValue           ::= '(' (StrValue (',' StrValue)*)* ')'
//                             | Identifier
//     Field               ::= FieldName('[' FieldArg ']')?
//     FieldArg            ::= QuotedStr | FieldArgBareStr
//     NumValue            ::= HexNumber | Number
//     StrValue            ::= QuotedStr | BareStr
//
// Supported Check Operators (EBNF Syntax):
//     UnaryOperator       ::= 'exists'
//     NumOperator         ::= '<=' | '<' | '>=' | '>'
//     StrOperator         ::= '==' | '=' | '!='
//                             | 'glob ' | 'iglob '
//                             | 'contains ' | 'icontains ' | 'bcontains '
//                             | 'startswith ' | 'bstartswith ' | 'endswith '
//     ListOperator        ::= 'intersects' | 'in' | 'pmatch'
//     FieldTransformerVal    ::= 'val('
//     FieldTransformerType   ::= 'tolower(' | 'toupper(' | 'b64(' | 'basename(' | 'len('
//
// Tokens (Regular Expressions):
//     Identifier          ::= [a-zA-Z]+[a-zA-Z0-9_]*
//     FieldName           ::= [a-zA-Z]+[a-zA-Z0-9_]*(\.[a-zA-Z]+[a-zA-Z0-9_]*)+
//     FieldArgBareStr     ::= [^ \b\t\n\r\[\]"']+
//     HexNumber           ::= 0[xX][0-9a-zA-Z]+
//     Number              ::= [+\-]?[0-9]+[\.]?[0-9]*([eE][+\-][0-9]+)?
//     QuotedStr           ::= "(?:\\"|.)*?"|'(?:\\'|.)*?'
//     BareStr             ::= [^ \b\t\n\r\(\),="']+
//

namespace libsinsp {
namespace filter {

/*!
    \brief This class parses a sinsp filter string with a context-free
    formal grammar and generates an AST.
*/
class SINSP_PUBLIC parser {
public:
	/*!
	    \brief Returns the set of filtering operators supported by libsinsp
	*/
	static std::vector<std::string> supported_operators(bool list_only = false);

	/*!
	    \brief Returns the set of field transformers supported by libsinsp
	*/
	static std::vector<std::string> supported_field_transformers(bool include_val = false);

	/*!
	    \brief Constructs the parser with a given filter string input
	    \param input The filter string to parse.
	*/
	explicit parser(const std::string& input);

	/*!
	    \brief Retrieves the parser position info.
	    \param pos pos_info struct in which the info is written.
	*/
	void get_pos(ast::pos_info& pos) const;

	/*!
	    \brief Retrieves the parser position info.
	    \return pos_info struct in which the info is written.
	*/
	ast::pos_info get_pos() const;

	/*!
	    \brief Sets the partial parsing option. Default is true.
	    \note Parsing the input partially means that the parsing can succeed
	    without reaching the end of the input. In other word, this allows
	    parsing strings that have a valid filter as their prefix.
	*/
	void set_parse_partial(bool parse_partial);

	/*!
	    \brief Sets the max depth of the recursion. Default is 100.
	    \note The parser is implemented as a recursive descent parser, so the
	    depth of the recursion is capped to a max level to prevent stack abuse.
	*/
	void set_max_depth(uint32_t max_depth);

	/*!
	    \brief Parses the input and returns an AST.
	    \note Throws a sinsp_exception in case of parsing errors.
	    \return Pointer to a expr struct representing the the parsed
	    AST. The resulting pointer is owned by the caller and must be deleted
	    by it. The pointer is automatically deleted in case of exception.
	    On delete, each node of the AST deletes all its subnodes.
	*/
	std::unique_ptr<ast::expr> parse();

private:
	std::unique_ptr<ast::expr> parse_or();
	std::unique_ptr<ast::expr> parse_and();
	std::unique_ptr<ast::expr> parse_not();
	std::unique_ptr<ast::expr> parse_embedded_remainder();
	std::unique_ptr<ast::expr> parse_check();
	std::unique_ptr<ast::expr> parse_list_value();
	std::unique_ptr<ast::expr> parse_field_remainder(std::string fieldname,
	                                                 const libsinsp::filter::ast::pos_info& pos);
	std::unique_ptr<ast::expr> parse_field_or_transformer_remainder(
	        std::string transformer,
	        const libsinsp::filter::ast::pos_info& pos);
	std::unique_ptr<ast::expr> parse_condition(std::unique_ptr<ast::expr> left,
	                                           const libsinsp::filter::ast::pos_info& pos);
	std::unique_ptr<ast::expr> parse_list_value_or_transformer();
	std::unique_ptr<ast::expr> parse_num_value_or_transformer();
	std::unique_ptr<ast::expr> parse_str_value_or_transformer(bool no_transformer);
	std::unique_ptr<ast::expr> try_parse_transformer_or_val();
	inline bool lex_blank();
	inline bool lex_identifier();
	inline bool lex_field_name();
	inline bool lex_field_arg_bare_str();
	inline bool lex_hex_num();
	inline bool lex_num();
	inline bool lex_quoted_str();
	inline bool lex_bare_str();
	inline bool lex_unary_op();
	inline bool lex_num_op();
	inline bool lex_str_op();
	inline bool lex_list_op();
	inline bool lex_field_transformer_val();
	inline bool lex_field_transformer_type();
	inline bool lex_helper_rgx(const re2::RE2& rgx);
	inline bool lex_helper_str(const std::string& str);
	inline bool lex_helper_str_list(const std::vector<std::string>& list);
	inline bool lex_helper_operator_list(const std::vector<std::string>& list);
	inline const char* cursor();
	inline std::string trim_str(std::string str);

	bool m_parse_partial;
	uint32_t m_depth;
	uint32_t m_max_depth;
	ast::pos_info m_pos;
	std::string m_input;
	std::string m_last_token;
};

}  // namespace filter
}  // namespace libsinsp

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

#pragma once

#include "ast.h"

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
//     Check               ::= CheckField CheckCondition
//                             | Identifier
//                             | '(' Expr ')'
//     CheckCondition      ::= UnaryOperator
//                             | NumOperator NumValue
//                             | StrOperator StrValue
//                             | ListOperator ListValue
//     ListValue           ::= '(' (StrValue (',' StrValue)*)* ')'
//                             | Identifier
//     CheckField          ::= FieldName('[' FieldArg ']')?
//     FieldArg            ::= QuotedStr | FieldArgBareStr 
//     NumValue            ::= HexNumber | Number
//     StrValue            ::= QuotedStr | BareStr
// 
// Supported Check Operators (EBNF Syntax):
//     UnaryOperator       ::= 'exists'
//     NumOperator         ::= '<=' | '<' | '>=' | '>' 
//     StrOperator         ::= '==' | '=' | '!=' | 'glob ' | 'contains '
//                             | 'icontains ' | 'startswith ' | 'endswith '
//     ListOperator        ::= 'intersects' | 'in' | 'pmatch' 
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
class SINSP_PUBLIC parser
{
public:
	/*!
		\brief A struct containing info about the position of the parser
		relatively to the string input. For example, this can either be used
		to retrieve context information when an exception is thrown.
	*/
	struct pos_info
	{
		inline void reset() 
		{
			idx = 0;
			line = 1;
			col = 1;
		}
		
		inline std::string as_string() const
		{
			return "index " + std::to_string(idx) 
				+ ", line " + std::to_string(line) 
				+ ", column " + std::to_string(col);
		}

		uint32_t idx;
		uint32_t line;
		uint32_t col;
	};

	/*!
		\brief Returns the set of filtering operators supported by libsinsp
	*/
	static std::vector<std::string> supported_operators(bool list_only=false);

	/*!
		\brief Constructs the parser with a given filter string input
		\param input The filter string to parse.
	*/
	explicit parser(const std::string& input);

	/*!
		\brief Retrieves the parser position info.
		\param pos pos_info struct in which the info is written.
	*/
	void get_pos(pos_info& pos) const;

	/*!
		\brief Retrieves the parser position info.
		\return pos_info struct in which the info is written.
	*/
	pos_info get_pos() const;

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
	ast::expr* parse();

private:
	ast::expr* parse_or();
	ast::expr* parse_and();
	ast::expr* parse_not();
	ast::expr* parse_embedded_remainder();
	ast::expr* parse_check();
	ast::expr* parse_list_value();
	ast::value_expr* parse_num_value();
	ast::value_expr* parse_str_value();
	bool lex_blank();
	bool lex_identifier();
	bool lex_field_name();
	bool lex_field_arg_bare_str();
	bool lex_hex_num();
	bool lex_num();
	bool lex_quoted_str();
	bool lex_bare_str();
	bool lex_unary_op();
	bool lex_num_op();
	bool lex_str_op();
	bool lex_list_op();
	bool lex_helper_rgx(std::string rgx);
	bool lex_helper_str(const std::string& str);
	bool lex_helper_str_list(const std::vector<std::string>& list);
	void depth_push();
	void depth_pop();
	const char* cursor();
	std::string trim_str(std::string str);

	bool m_parse_partial;
	uint32_t m_depth;
	uint32_t m_max_depth;
	pos_info m_pos;
	std::string m_input;
	std::string m_last_token;
};

}
}

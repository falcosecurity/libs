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

#include <libsinsp/filter_check_list.h>
#include <libsinsp/sinsp_filtercheck.h>
#include <libsinsp/filter/parser.h>

#include <set>
#include <string>
#include <vector>
#include <memory>

/** @defgroup filter Filtering events
 * Filtering infrastructure.
 *  @{
 */

///////////////////////////////////////////////////////////////////////////////
// Filter expression class
// A filter expression contains multiple filters connected by boolean expressions,
// e.g. "check or check", "check and check and check", "not check"
///////////////////////////////////////////////////////////////////////////////
class sinsp_filter_expression : public sinsp_filter_check
{
public:
	sinsp_filter_expression() = default;
	virtual ~sinsp_filter_expression() = default;

	//
	// The following methods are part of the filter check interface but are irrelevant
	// for this class, because they are used only for the leaves of the filtering tree.
	//
	int32_t parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering) override
	{
		return 0;
	}

	void add_filter_value(const char* str, uint32_t len, uint32_t i = 0) override
	{
		return;
	}

	bool compare(sinsp_evt*) override;
	bool extract(sinsp_evt*, std::vector<extract_value_t>& values, bool sanitize_strings = true) override;

	void add_check(std::unique_ptr<sinsp_filter_check> chk);

	//
	// An expression is consistent if all its checks are of the same type (or/and).
	//
	// This method returns the expression operator (BO_AND/BO_OR/BO_NONE) if the
	// expression is consistent. It returns -1 if the expression is not consistent.
	//
	int32_t get_expr_boolop() const;

	sinsp_filter_expression* m_parent = nullptr;
	std::vector<std::unique_ptr<sinsp_filter_check>> m_checks;
};


/*!
  \brief This is the class that runs the filters.
*/
class SINSP_PUBLIC sinsp_filter
{
public:
	sinsp_filter(sinsp* inspector);
	virtual ~sinsp_filter() = default;

	bool run(sinsp_evt *evt);

	void push_expression(boolop op);
	void pop_expression();
	void add_check(std::unique_ptr<sinsp_filter_check> chk);

	std::unique_ptr<sinsp_filter_expression> m_filter;

private:
	sinsp_filter_expression* m_curexpr;

	sinsp* m_inspector;
};

class sinsp_filter_factory
{
public:
	// A struct describing a single filtercheck field ("ka.user")
	struct filter_field_info
	{
		// The name of the field
		std::string name;

		// A description of the field
		std::string desc;

		// The data type for the field
		std::string data_type;

		// A set of free-form tags for the field. Examples include:
		// FILTER ONLY: for fields that can only be used in filters, not outputs.
		// IDX_REQUIRED: for fields that can take an optional index
		// EPF_TABLE_ONLY: for fields with the EPF_TABLE_ONLY (e.g. hidden) flag set
		// etc
		std::set<std::string> tags;

		bool is_skippable() const;
		bool is_deprecated() const;
	};

	// Describes a group of filtercheck fields ("ka")
	class filter_fieldclass_info
	{
	public:
		// The name of the group of fields
		std::string name;

		// A description for the fields
		std::string desc;

		// A short (< 10 words) description of the fields. Can be blank.
		std::string shortdesc;

		std::list<filter_field_info> fields;

		// Print a terminal-friendly representation of this
		// field class, including name, description, supported
		// event sources, and the name and description of each field.
		std::string as_string(bool verbose, const std::set<std::string>& event_sources = std::set<std::string>(), bool include_deprecated=false);

		// Print a markdown representation of this
		// field class, suitable for publication on the documentation
		// website.
		std::string as_markdown(const std::set<std::string>& event_sources = std::set<std::string>(), bool include_deprecated=false);

		// How far to right-justify the name/description/etc block.
		static uint32_t s_rightblock_start;

		// How wide the overall output should be.
		static uint32_t s_width;

	private:
		void wrapstring(const std::string &in, std::ostringstream &os);
	};

	sinsp_filter_factory(sinsp *inspector, filter_check_list &available_checks);

	virtual ~sinsp_filter_factory() = default;

	virtual std::unique_ptr<sinsp_filter> new_filter() const;
	
	virtual std::unique_ptr<sinsp_filter_check> new_filtercheck(const char* fldname) const;

	virtual std::list<filter_fieldclass_info> get_fields() const;

	// Convienence method to convert a vector of
	// filter_check_infos into a list of
	// filter_fieldclass_infos. This is useful for programs that
	// use filterchecks but not factories.
	static std::list<filter_fieldclass_info> check_infos_to_fieldclass_infos(
		const std::vector<const filter_check_info*> &fc_plugins);

protected:
	sinsp *m_inspector;
	filter_check_list &m_available_checks;
};

/*!
  \brief This is the class that compiles the filters.
*/
class SINSP_PUBLIC sinsp_filter_compiler:
	private libsinsp::filter::ast::const_expr_visitor
{
public:
	/*!
		\brief Constructs the compiler

		\param inspector Pointer to the inspector instance that will generate
		the events to be filtered
		\param fltstr The filter string to compile

		\note This is not the primary constructor, and is only maintained for
		backward compatibility
	*/
	sinsp_filter_compiler(
		sinsp* inspector,
		const std::string& fltstr);

	/*!
		\brief Constructs the compiler

		\param factory Pointer to a filter factory to be used to build
		the filtercheck tree
		\param fltstr The filter string to compile
	*/
	sinsp_filter_compiler(
		std::shared_ptr<sinsp_filter_factory> factory,
		const std::string& fltstr);

	/*!
		\brief Constructs the compiler

		\param factory Pointer to a filter factory to be used to build
		the filtercheck tree
		\param fltast AST of a parsed filter, used to build the filtercheck
		tree
	*/
	sinsp_filter_compiler(
		std::shared_ptr<sinsp_filter_factory> factory,
		const libsinsp::filter::ast::expr* fltast);

	/*!
		\brief Builds a filtercheck tree and bundles it in sinsp_filter
		\return The resulting pointer is owned by the caller and must be deleted
		by it. The pointer is automatically deleted in case of exception.
		\note Throws a sinsp_exception if the filter syntax is not valid
	*/
	std::unique_ptr<sinsp_filter> compile();

	std::shared_ptr<const libsinsp::filter::ast::expr> get_filter_ast() const { return m_internal_flt_ast; }

	std::shared_ptr<libsinsp::filter::ast::expr> get_filter_ast() { return m_internal_flt_ast; }

	const libsinsp::filter::ast::pos_info& get_pos() const { return m_pos; }

private:
	void visit(const libsinsp::filter::ast::and_expr*) override;
	void visit(const libsinsp::filter::ast::or_expr*) override;
	void visit(const libsinsp::filter::ast::not_expr*) override;
	void visit(const libsinsp::filter::ast::value_expr*) override;
	void visit(const libsinsp::filter::ast::list_expr*) override;
	void visit(const libsinsp::filter::ast::unary_check_expr*) override;
	void visit(const libsinsp::filter::ast::binary_check_expr*) override;
	cmpop str_to_cmpop(const std::string& str);
	std::string create_filtercheck_name(const std::string& name, const std::string& arg);
	std::unique_ptr<sinsp_filter_check> create_filtercheck(std::string& field);

	libsinsp::filter::ast::pos_info m_pos;
	bool m_expect_values;
	boolop m_last_boolop;
	std::string m_flt_str;
	std::unique_ptr<sinsp_filter> m_filter;
	std::vector<std::string> m_field_values;
	std::shared_ptr<libsinsp::filter::ast::expr> m_internal_flt_ast;
	const libsinsp::filter::ast::expr* m_flt_ast;
	std::shared_ptr<sinsp_filter_factory> m_factory;
	sinsp_filter_check_list m_default_filterlist;
};

/*@}*/
/*
Copyright (C) 2021 The Falco Authors.

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

#include <set>
#include <string>
#include <vector>


#include "filter_check_list.h"
#include "gen_filter.h"
#include "filter/parser.h"

/** @defgroup filter Filtering events
 * Filtering infrastructure.
 *  @{
 */

/*!
  \brief This is the class that runs the filters.
*/
class SINSP_PUBLIC sinsp_filter : public gen_event_filter
{
public:
	sinsp_filter(sinsp* inspector);
	~sinsp_filter();

private:
	sinsp* m_inspector;

	friend class sinsp_evt_formatter;
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
		\param ttable_only For internal use only

		\note This is not the primary constructor, and is only maintained for
		backward compatibility
	*/
	sinsp_filter_compiler(
		sinsp* inspector,
		const std::string& fltstr,
		bool ttable_only=false);

	/*!
		\brief Constructs the compiler

		\param factory Pointer to a filter factory to be used to build
		the filtercheck tree
		\param fltstr The filter string to compile
		\param ttable_only For internal use only
	*/
	sinsp_filter_compiler(
		std::shared_ptr<gen_event_filter_factory> factory,
		const std::string& fltstr,
		bool ttable_only=false);

	/*!
		\brief Constructs the compiler

		\param factory Pointer to a filter factory to be used to build
		the filtercheck tree
		\param fltast AST of a parsed filter, used to build the filtercheck
		tree
		\param ttable_only For internal use only
	*/
	sinsp_filter_compiler(
		std::shared_ptr<gen_event_filter_factory> factory,
		const libsinsp::filter::ast::expr* fltast,
		bool ttable_only=false);

	/*!
		\brief Builds a filtercheck tree and bundles it in sinsp_filter
		\return The resulting pointer is owned by the caller and must be deleted
		by it. The pointer is automatically deleted in case of exception.
		\note Throws a sinsp_exception if the filter syntax is not valid
	*/
	sinsp_filter* compile();

	const libsinsp::filter::ast::pos_info& get_pos() const { return m_pos; }

private:
	void visit(const libsinsp::filter::ast::and_expr*) override;
	void visit(const libsinsp::filter::ast::or_expr*) override;
	void visit(const libsinsp::filter::ast::not_expr*) override;
	void visit(const libsinsp::filter::ast::value_expr*) override;
	void visit(const libsinsp::filter::ast::list_expr*) override;
	void visit(const libsinsp::filter::ast::unary_check_expr*) override;
	void visit(const libsinsp::filter::ast::binary_check_expr*) override;
	void check_ttable_only(std::string& field, gen_event_filter_check *check);
	cmpop str_to_cmpop(const std::string& str);
	std::string create_filtercheck_name(const std::string& name, const std::string& arg);
	gen_event_filter_check* create_filtercheck(std::string& field);

	libsinsp::filter::ast::pos_info m_pos;
	bool m_ttable_only;
	bool m_expect_values;
	boolop m_last_boolop;
	std::string m_flt_str;
	sinsp_filter* m_filter;
	std::vector<std::string> m_field_values;
	std::unique_ptr<libsinsp::filter::ast::expr> m_internal_flt_ast;
	const libsinsp::filter::ast::expr* m_flt_ast;
	std::shared_ptr<gen_event_filter_factory> m_factory;

	friend class sinsp_evt_formatter;
};

/*@}*/

class sinsp_filter_factory : public gen_event_filter_factory
{
public:
	sinsp_filter_factory(sinsp *inspector, filter_check_list &available_checks=g_filterlist);

	virtual ~sinsp_filter_factory();

	gen_event_filter *new_filter();

	gen_event_filter_check *new_filtercheck(const char *fldname);

	std::list<gen_event_filter_factory::filter_fieldclass_info> get_fields() override;

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


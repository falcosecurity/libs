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
#include <vector>


#include "filter_check_list.h"
#include "gen_filter.h"

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
class SINSP_PUBLIC sinsp_filter_compiler
{
public:
	/*!
	  \brief Constructs the compiler.

	  \param inspector Pointer to the inspector instance that will generate the
	   events to be filtered.
	  \param fltstr the filter string to compile.
	  \param ttable_only for internal use only.

	 \note Throws a sinsp_exception if the filter syntax is not valid.
	*/
	sinsp_filter_compiler(sinsp* inspector/* xxx needed? */, const string& fltstr, bool ttable_only=false);

	~sinsp_filter_compiler();

	sinsp_filter* compile();

private:
	enum state
	{
		ST_EXPRESSION_DONE,
		ST_NEED_EXPRESSION,
	};

	sinsp_filter* compile_();

	char next();
	bool compare_no_consume(const string& str);

	vector<char> next_operand(bool expecting_first_operand, bool in_clause);
	cmpop next_comparison_operator();
	void parse_check();

	static bool isblank(char c);
	static bool is_special_char(char c);
	static bool is_bracket(char c);

	sinsp* m_inspector;
	bool m_ttable_only;

	string m_fltstr;
	int32_t m_scanpos;
	int32_t m_scansize;
	state m_state;
	boolop m_last_boolop;
	int32_t m_nest_level;

	sinsp_filter* m_filter;

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
		const vector<const filter_check_info*> &fc_plugins);

protected:
	sinsp *m_inspector;
	filter_check_list &m_available_checks;
};


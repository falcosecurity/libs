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

#include <set>
#include <list>
#include <map>
#include <memory>
#include <string>
#include <vector>

/*
 * Operators to compare events
 */
enum cmpop {
	CO_NONE = 0,
	CO_EQ = 1,
	CO_NE = 2,
	CO_LT = 3,
	CO_LE = 4,
	CO_GT = 5,
	CO_GE = 6,
	CO_CONTAINS = 7,
	CO_IN = 8,
	CO_EXISTS = 9,
	CO_ICONTAINS = 10,
	CO_STARTSWITH = 11,
	CO_GLOB = 12,
	CO_PMATCH = 13,
	CO_ENDSWITH = 14,
	CO_INTERSECTS = 15,
	CO_BCONTAINS = 16,
	CO_BSTARTSWITH = 17,
};

enum boolop
{
	BO_NONE = 0,
	BO_NOT = 1,
	BO_OR = 2,
	BO_AND = 4,

	// obtained by bitwise OR'ing with one of above ops
	BO_ORNOT = 3,
	BO_ANDNOT = 5,
};

namespace std
{
std::string to_string(cmpop);
std::string to_string(boolop);
}

enum evt_src
{
	ESRC_NONE = 0,
	ESRC_SINSP = 1,
	ESRC_K8S_AUDIT = 2,
	ESRC_MAX = 3,
};

class gen_event
{
public:
	gen_event();
	virtual ~gen_event();

	// Every event must expose a timestamp
	virtual uint64_t get_ts() const = 0;

	/*!
	  \brief Get the source of the event.
	*/
	virtual uint16_t get_source() const = 0;

	/*!
	  \brief Get the type of the event.
	*/
	virtual uint16_t get_type() const = 0;

};

typedef struct extract_value {
	uint8_t* ptr;
	uint32_t len;
} extract_value_t;

class gen_event_filter_check
{
public:
	gen_event_filter_check();
	virtual ~gen_event_filter_check();

	boolop m_boolop;
	cmpop m_cmpop;

	size_t m_hits = 0;
	size_t m_cached = 0;
	size_t m_matched_true = 0;

	virtual int32_t parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering) = 0;
	virtual void add_filter_value(const char* str, uint32_t len, uint32_t i = 0 ) = 0;
	virtual bool compare(gen_event *evt) = 0;
	virtual bool extract(gen_event *evt, std::vector<extract_value_t>& values, bool sanitize_strings = true) = 0;
};

///////////////////////////////////////////////////////////////////////////////
// Filter expression class
// A filter expression contains multiple filters connected by boolean expressions,
// e.g. "check or check", "check and check and check", "not check"
///////////////////////////////////////////////////////////////////////////////

class gen_event_filter_expression : public gen_event_filter_check
{
public:
	gen_event_filter_expression();
	virtual ~gen_event_filter_expression();

	//
	// The following methods are part of the filter check interface but are irrelevant
	// for this class, because they are used only for the leaves of the filtering tree.
	//
	int32_t parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering)
	{
		return 0;
	}

	void add_filter_value(const char* str, uint32_t len, uint32_t i = 0 )
	{
		return;
	}

	void add_check(gen_event_filter_check* chk);

	bool compare(gen_event *evt);

	bool extract(gen_event *evt, std::vector<extract_value_t>& values, bool sanitize_strings = true);

	//
	// An expression is consistent if all its checks are of the same type (or/and).
	//
	// This method returns the expression operator (BO_AND/BO_OR/BO_NONE) if the
	// expression is consistent. It returns -1 if the expression is not consistent.
	//
	int32_t get_expr_boolop();

	gen_event_filter_expression* m_parent;
	std::vector<gen_event_filter_check*> m_checks;
};



class gen_event_filter
{
public:
	gen_event_filter();

	virtual ~gen_event_filter();

	/*!
	  \brief Applies the filter to the given event.

	  \param evt Pointer that needs to be filtered.
	  \return true if the event is accepted by the filter, false if it's rejected.
	*/
	bool run(gen_event *evt);
	void push_expression(boolop op);
	void pop_expression();
	void add_check(gen_event_filter_check* chk);

	gen_event_filter_expression* m_filter;

protected:
	gen_event_filter_expression* m_curexpr;

	friend class sinsp_filter_compiler;
	friend class sinsp_filter_optimizer;
};

class gen_event_filter_factory
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

		bool is_skippable();
		bool is_deprecated();
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

	gen_event_filter_factory() {};
	virtual ~gen_event_filter_factory() {};

	// Create a new filter
	virtual gen_event_filter *new_filter() = 0;

	// Create a new filtercheck
	virtual gen_event_filter_check *new_filtercheck(const char *fldname) = 0;

	// Return the set of fields supported by this factory
	virtual std::list<filter_fieldclass_info> get_fields() = 0;
};

class gen_event_formatter
{
public:
	enum output_format {
		OF_NORMAL = 0,
		OF_JSON   = 1
	};

	gen_event_formatter();
	virtual ~gen_event_formatter();

	virtual void set_format(output_format of, const std::string &format) = 0;

	// Format the output string with the configured format
	virtual bool tostring(gen_event *evt, std::string &output) = 0;

	// In some cases, it may be useful to format an output string
	// with a custom format.
	virtual bool tostring_withformat(gen_event *evt, std::string &output, output_format of) = 0;

	// The map should map from field name, without the '%'
	// (e.g. "proc.name"), to field value (e.g. "nginx")
	virtual bool get_field_values(gen_event *evt, std::map<std::string, std::string> &fields) = 0;

	virtual void get_field_names(std::vector<std::string> &fields) = 0;

	virtual output_format get_output_format() = 0;
};


class gen_event_formatter_factory
{
public:
	gen_event_formatter_factory();
	virtual ~gen_event_formatter_factory();

	// This should be called before any calls to
	// create_formatter(), and changes the output format of new
	// formatters.
	virtual void set_output_format(gen_event_formatter::output_format of) = 0;

	virtual std::shared_ptr<gen_event_formatter> create_formatter(const std::string &format) = 0;
};

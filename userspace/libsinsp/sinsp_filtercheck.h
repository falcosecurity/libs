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

#include <string>
#include <unordered_set>
#include <memory>
#include <json/json.h>
#include <libscap/scap.h>
#include <libsinsp/tuples.h>
#include <libsinsp/filter_value.h>
#include <libsinsp/prefix_search.h>
#include <libsinsp/event.h>

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
	CO_IGLOB = 18,
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

bool flt_compare(cmpop op, ppm_param_type type, const void* operand1, const void* operand2, uint32_t op1_len = 0, uint32_t op2_len = 0);
bool flt_compare_avg(cmpop op, ppm_param_type type, const void* operand1, const void* operand2, uint32_t op1_len, uint32_t op2_len, uint32_t cnt1, uint32_t cnt2);
bool flt_compare_ipv4net(cmpop op, uint64_t operand1, const ipv4net* operand2);
bool flt_compare_ipv6net(cmpop op, const ipv6addr *operand1, const ipv6net *operand2);

namespace std
{
std::string to_string(cmpop);
std::string to_string(boolop);
}

struct extract_value_t {
	uint8_t* ptr = nullptr;
	uint32_t len = 0;
};

class check_extraction_cache_entry
{
public:
	uint64_t m_evtnum = UINT64_MAX;
	std::vector<extract_value_t> m_res;
};

class check_eval_cache_entry
{
public:
	uint64_t m_evtnum = UINT64_MAX;
	bool m_res = false;
};

class check_cache_metrics
{
public:
	// The number of times extract() was called
	uint64_t m_num_extract = 0;

	// The number of times extract() could use a cached value
	uint64_t m_num_extract_cache = 0;

	// The number of times compare() was called
	uint64_t m_num_eval = 0;

	// The number of times compare() could use a cached value
	uint64_t m_num_eval_cache = 0;
};

/*!
  \brief Information about a filter/formatting field.
*/
struct filtercheck_field_info
{
	ppm_param_type m_type = PT_NONE; ///< Field type.
	uint32_t m_flags = 0;  ///< Field flags.
	ppm_print_format m_print_format = PF_NA;  ///< If this is a numeric field, this flag specifies if it should be rendered as octal, decimal or hex.
	char m_name[64];  ///< Field name.
	char m_display[64];  ///< Field display name (short description). May be empty.
	char m_description[1024];  ///< Field description.
};

/*!
  \brief Information about a group of filter/formatting fields.
*/
class filter_check_info
{
public:
	enum flags
	{
		FL_NONE = 0,
		FL_HIDDEN = (1 << 0),	///< This filter check class won't be shown by fields/filter listings.
	};

	std::string m_name; ///< Field class name.
	std::string m_shortdesc; ///< short (< 10 words) description of this filtercheck. Can be blank.
	std::string m_desc; ///< Field class description.
	int32_t m_nfields = 0; ///< Number of fields in this field group.
	const filtercheck_field_info* m_fields = nullptr; ///< Array containing m_nfields field descriptions.
	uint32_t m_flags = FL_NONE;
};

///////////////////////////////////////////////////////////////////////////////
// The filter check interface
// NOTE: in order to add a new type of filter check, you need to add a class for
//       it and then add it to new_filter_check_from_name.
///////////////////////////////////////////////////////////////////////////////
class sinsp_filter_check
{
public:
	sinsp_filter_check();
	virtual ~sinsp_filter_check() = default;

	//
	// Sets an inspector to be used internally.
	//
	void set_inspector(sinsp* inspector);

	//
	// Allocate a new check of the same type.
	// Every filtercheck plugin must implement this.
	//
	virtual std::unique_ptr<sinsp_filter_check> allocate_new()
	{
		throw sinsp_exception("can't clone abstract sinsp_filter_check");
	}

	//
	// Get the list of fields that this check exports
	//
	virtual const filter_check_info* get_fields() const
	{
		return &m_info;
	}

	//
	// Parse the name of the field.
	// Returns the length of the parsed field if successful, an exception in
	// case of error.
	//
	virtual int32_t parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering);

	//
	// If this check is used by a filter, extract the constant to compare it to
	// Doesn't return the field length because the filtering engine can calculate it.
	//
	virtual void add_filter_value(const char* str, uint32_t len, uint32_t i = 0);

	//
	// Return the info about the field that this instance contains
	//
	virtual const filtercheck_field_info* get_field_info() const;

	//
	// Return true if this filtercheck can have an argument,
	// either due to being required (flag EPF_ARG_REQUIRED) or
	// allowed (flag EPF_ARG_ALLOWED).
	//
	bool can_have_argument() const;

	//
	// Extract the field from the event. In sanitize_strings is true, any
	// string values are sanitized to remove nonprintable characters.
	// By default, this fills the vector with only one value, retireved by calling the single-result
	// extract method.
	// If a NULL value is returned by extract, the vector is emptied.
	// Subclasses are meant to either override this, or the single-valued extract method.
	virtual bool extract(sinsp_evt*, OUT std::vector<extract_value_t>& values, bool sanitize_strings = true);

	//
	// Compare the field with the constant value obtained from parse_filter_value()
	//
	virtual bool compare(sinsp_evt*);

	//
	// Extract the value from the event and convert it into a string
	//
	virtual char* tostring(sinsp_evt* evt);

	//
	// Extract the value from the event and convert it into a Json value
	// or object
	//
	virtual Json::Value tojson(sinsp_evt* evt);

	sinsp* m_inspector = nullptr;
	std::vector<extract_value_t> m_extracted_values;
	check_eval_cache_entry* m_eval_cache_entry = nullptr;
	check_extraction_cache_entry* m_extraction_cache_entry = nullptr;
	check_cache_metrics *m_cache_metrics = nullptr;
	boolop m_boolop = BO_NONE;
	cmpop m_cmpop = CO_NONE;

	char* rawval_to_string(uint8_t* rawval,
			       ppm_param_type ptype,
			       ppm_print_format print_format,
			       uint32_t len);

	inline const std::vector<filter_value_t>& get_filter_values() const
	{
		return m_vals;
	}

protected:
	virtual bool compare_nocache(sinsp_evt*);

	virtual Json::Value extract_as_js(sinsp_evt*, OUT uint32_t* len)
	{
		return Json::nullValue;
	}

	virtual size_t parse_filter_value(const char* str, uint32_t len, uint8_t *storage, uint32_t storage_len);

	// This is a single-value version of extract for subclasses non supporting extracting
	// multiple values. By default, this returns NULL.
	// Subclasses are meant to either override this, or the multi-valued extract method.
	bool extract_nocache(sinsp_evt *evt, OUT std::vector<extract_value_t>& values, bool sanitize_strings = true);
	virtual uint8_t* extract(sinsp_evt*, OUT uint32_t* len, bool sanitize_strings = true);

	bool compare_rhs(cmpop op, ppm_param_type type, const void* operand1, uint32_t op1_len = 0);
	bool compare_rhs(cmpop op, ppm_param_type type, std::vector<extract_value_t>& values);

	Json::Value rawval_to_json(uint8_t* rawval, ppm_param_type ptype, ppm_print_format print_format, uint32_t len);

	inline uint8_t* filter_value_p(uint16_t i = 0) { return &m_val_storages[i][0]; }
	inline std::vector<uint8_t>* filter_value(uint16_t i = 0) { return &m_val_storages[i]; }

	std::vector<char> m_getpropertystr_storage;
	std::vector<std::vector<uint8_t>> m_val_storages;

	std::vector<filter_value_t> m_vals;

	const filtercheck_field_info* m_field = nullptr;
	filter_check_info m_info;
	uint32_t m_field_id = (uint32_t) -1;

private:

	// used for comparing right-hand single value
	uint32_t m_val_storage_len;

	// used for comparing right-hand lists of values
	std::unordered_set<filter_value_t,
		g_hash_membuf,
		g_equal_to_membuf> m_val_storages_members;
	path_prefix_search m_val_storages_paths;
	uint32_t m_val_storages_min_size;
	uint32_t m_val_storages_max_size;
};

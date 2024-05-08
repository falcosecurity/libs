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

#include <libsinsp/filter_value.h>
#include <libsinsp/prefix_search.h>
#include <libsinsp/event.h>
#include <libsinsp/filter_compare.h>
#include <libsinsp/sinsp_filter_transformer.h>

#include <json/json.h>

#include <string>
#include <unordered_set>
#include <memory>

enum boolop: uint8_t
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
std::string to_string(boolop);
}

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

	//
	// Return true if this field must have an argument
	//
	inline bool is_arg_required() const
	{
		return m_flags & EPF_ARG_REQUIRED;
	}

	//
	// Return true if this field can optionally have an argument
	//
	inline bool is_arg_allowed() const
	{
		return m_flags & EPF_ARG_REQUIRED;
	}

	//
	// Returns true if this field can have an argument, either
	// optionally or mandatorily
	//
	inline bool is_arg_supported() const
	{
		return (m_flags & EPF_ARG_REQUIRED) ||(m_flags & EPF_ARG_ALLOWED);
	}

	//
	// Returns true if this field is a list of values
	//
	inline bool is_list() const
	{
		return m_flags & EPF_IS_LIST;
	}

	//
	// Returns true if this filter check can support a rhs filter check instead of a const value.
	//
	inline bool is_rhs_field_supported() const
	{
		return !(m_flags & EPF_NO_RHS);
	}

	//
	// Returns true if this filter check can support an extraction transformer on it.
	//
	inline bool is_transformer_supported() const
	{
		return !(m_flags & EPF_NO_TRANSFORMER);
	}
};

/*!
  \brief Information about a group of filter/formatting fields.
*/
class filter_check_info
{
public:
	enum flags: uint8_t
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
		return m_info;
	}

	//
	// Return the info about the field that this instance contains
	// This must be used only after `parse_field_name`
	//
	virtual const filtercheck_field_info* get_field_info() const
	{
		return m_field;
	}

	//
	// Parse the name of the field.
	// Returns the length of the parsed field if successful, an exception in
	// case of error.
	//
	virtual int32_t parse_field_name(std::string_view, bool alloc_state, bool needed_for_filtering);

	//
	// If this check is used by a filter, extract the constant to compare it to
	// Doesn't return the field length because the filtering engine can calculate it.
	//
	virtual void add_filter_value(const char* str, uint32_t len, uint32_t i = 0);

	//
	// If this check is used by a filter, extract the rhs filter check to compare it to.
	//
	virtual void add_filter_value(std::unique_ptr<sinsp_filter_check> chk);

	//
	// Return the right-hand side constant values used for comparison
	//
	virtual const std::vector<filter_value_t>& get_filter_values() const
	{
		return m_vals;
	}

	//
	// Return true if the filter check is compared against another filter check
	//
	virtual bool has_filtercheck_value() const
	{
		return m_rhs_filter_check.get() != nullptr;
	}

	//
	// Add extract transformers to the filter check
	//
	virtual void add_transformer(filter_transformer_type trtype);

	//
	// Return true if the filter check contains field transformers
	//
	virtual bool has_transformers() const
	{
		return !m_transformers.empty();
	}

	//
	// Return the type of the current field after applying
	// all the configured transformers
	//
	virtual const filtercheck_field_info* get_transformed_field_info() const
	{
		if (m_transformed_field != nullptr)
		{
			return m_transformed_field.get();
		}
		return get_field_info();
	}

	//
	// Extract the field from the event. If sanitize_strings is true, any
	// string values are sanitized to remove nonprintable characters.
	// By default, this fills the vector with only one value, retireved by calling the single-result
	// extract method.
	// If a NULL value is returned by extract, the vector is emptied.
	// Subclasses are meant to either override this, or the single-valued extract method.
	//
	// \param values [out] the values extracted from the filter check
	virtual bool extract(sinsp_evt*, std::vector<extract_value_t>& values, bool sanitize_strings = true);

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


protected:
	virtual bool compare_nocache(sinsp_evt*);

	virtual Json::Value extract_as_js(sinsp_evt*, uint32_t* len)
	{
		return Json::nullValue;
	}

	//
	// If present, apply all the transformers on the current filter check
	// changing extracted values and the filter check type.
	//
	bool apply_transformers(std::vector<extract_value_t>& values);

	virtual size_t parse_filter_value(const char* str, uint32_t len, uint8_t *storage, uint32_t storage_len);

	// This is a single-value version of extract for subclasses non supporting extracting
	// multiple values. By default, this returns NULL.
	// Subclasses are meant to either override this, or the multi-valued extract method.
	//
	// \param values [out] the values extracted from the filter check
	bool extract_nocache(sinsp_evt *evt, std::vector<extract_value_t>& values, bool sanitize_strings = true);
	// \param len [out] length in bytes for the returned value
	virtual uint8_t* extract_single(sinsp_evt*, uint32_t* len, bool sanitize_strings = true);

	bool compare_rhs(cmpop op, ppm_param_type type, const void* operand1, uint32_t op1_len = 0);
	bool compare_rhs(cmpop op, ppm_param_type type, std::vector<extract_value_t>& values);

	Json::Value rawval_to_json(uint8_t* rawval, ppm_param_type ptype, ppm_print_format print_format, uint32_t len);

	inline uint8_t* filter_value_p(uint16_t i = 0)
	{
		ASSERT(i < m_vals.size());
		return m_vals[i].first;
	}

	inline uint32_t filter_value_len(uint16_t i = 0)
	{
		ASSERT(i < m_vals.size());
		return m_vals[i].second;
	}

	std::vector<char> m_getpropertystr_storage;
	std::vector<std::vector<uint8_t>> m_val_storages;

	std::vector<filter_value_t> m_vals;

	const filtercheck_field_info* m_field = nullptr;
	const filter_check_info* m_info = nullptr;
	uint32_t m_field_id = (uint32_t) -1;

private:
	//
	// Instead of populating the filter check values with const values extracted at
	// filter compile time, it populates the filter check values with values extracted
	// from a right-hand side filter check at runtime.
	//
	inline void populate_filter_values_with_rhs_extracted_values(const std::vector<extract_value_t>& values);
	inline void check_rhs_field_type_consistency() const;

	std::list<sinsp_filter_transformer> m_transformers;	
	std::unique_ptr<sinsp_filter_check> m_rhs_filter_check = nullptr;
	std::unique_ptr<filtercheck_field_info> m_transformed_field = nullptr;

	// used for comparing right-hand lists of values
	std::unique_ptr<
		std::unordered_set<filter_value_t,
			g_hash_membuf,
			g_equal_to_membuf>> m_val_storages_members;
	std::unique_ptr<path_prefix_search> m_val_storages_paths;
	uint32_t m_val_storages_min_size;
	uint32_t m_val_storages_max_size;

	static constexpr const size_t s_min_filter_value_buf_size = 16;
	static constexpr const size_t s_max_filter_value_buf_size = 256;
};

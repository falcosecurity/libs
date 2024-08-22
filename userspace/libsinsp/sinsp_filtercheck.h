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
#include <libsinsp/filter_field.h>
#include <libsinsp/filter_cache.h>
#include <libsinsp/sinsp_filter_transformer.h>

#include <nlohmann/json.hpp>

#include <string>
#include <unordered_set>
#include <memory>

namespace re2 { class RE2; };

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
	bool extract(sinsp_evt*, std::vector<extract_value_t>& values, bool sanitize_strings = true);

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
	virtual nlohmann::json tojson(sinsp_evt* evt);

	sinsp* m_inspector = nullptr;
	std::vector<extract_value_t> m_extracted_values;
	std::shared_ptr<sinsp_filter_compare_cache> m_compare_cache = nullptr;
	std::shared_ptr<sinsp_filter_extract_cache> m_extract_cache = nullptr;
	std::shared_ptr<sinsp_filter_cache_metrics> m_cache_metrics = nullptr;
	boolop m_boolop = BO_NONE;
	cmpop m_cmpop = CO_NONE;

	char* rawval_to_string(uint8_t* rawval,
			       ppm_param_type ptype,
			       ppm_print_format print_format,
			       uint32_t len);


protected:
	virtual bool compare_nocache(sinsp_evt*);

	virtual nlohmann::json extract_as_js(sinsp_evt*, uint32_t* len)
	{
		return nlohmann::json{};
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
	virtual bool extract_nocache(sinsp_evt *evt, std::vector<extract_value_t>& values, bool sanitize_strings = true);
	// \param len [out] length in bytes for the returned value
	virtual uint8_t* extract_single(sinsp_evt*, uint32_t* len, bool sanitize_strings = true);

	bool compare_rhs(cmpop op, ppm_param_type type, const void* operand1, uint32_t op1_len = 0);
	bool compare_rhs(cmpop op, ppm_param_type type, std::vector<extract_value_t>& values);

	nlohmann::json rawval_to_json(uint8_t* rawval, ppm_param_type ptype, ppm_print_format print_format, uint32_t len);

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

	struct default_re2_deleter { void operator()(re2::RE2* __ptr) const; };
	std::unique_ptr<re2::RE2, default_re2_deleter> m_val_regex;

	static constexpr const size_t s_min_filter_value_buf_size = 16;
	static constexpr const size_t s_max_filter_value_buf_size = 256;
};

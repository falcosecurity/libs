// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

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
#include <libscap/scap.h>

#include <cstdint>
#include <vector>
#include <string>

/**
 * @brief Flags used for describing a field used in a filter or in a formatter
 */
enum filtercheck_field_flags {
	EPF_NONE = 0,
	EPF_FILTER_ONLY = 1 << 0,  ///< this field can only be used as a filter.
	EPF_PRINT_ONLY = 1 << 1,   ///< this field can only be printed.
	EPF_ARG_REQUIRED =
	        1 << 2,  ///< this field includes an argument, under the form 'property.argument'.
	EPF_TABLE_ONLY = 1 << 3,  ///< this field is designed to be used in a table and won't appear in
	                          ///< the field listing.
	EPF_INFO = 1 << 4,        ///< this field contains summary information about the event.
	EPF_CONVERSATION = 1 << 5,     ///< this field can be used to identify conversations.
	EPF_IS_LIST = 1 << 6,          ///< this field is a list of values.
	EPF_ARG_ALLOWED = 1 << 7,      ///< this field optionally includes an argument.
	EPF_ARG_INDEX = 1 << 8,        ///< this field accepts numeric arguments.
	EPF_ARG_KEY = 1 << 9,          ///< this field accepts string arguments.
	EPF_DEPRECATED = 1 << 10,      ///< this field is deprecated.
	EPF_NO_TRANSFORMER = 1 << 11,  ///< this field cannot have a field transformer.
	EPF_NO_RHS = 1 << 12,  ///< this field cannot have a right-hand side filter check, and cannot be
	                       ///< used as a right-hand side filter check.
	EPF_NO_PTR_STABILITY =
	        1 << 13,  ///< data pointers extracted by this field may change across subsequent
	                  ///< extractions (even of other fields), which makes them unsafe to be used
	                  ///< with filter caching or field-to-field comparisons
	EPF_FORMAT_SUGGESTED = 1 << 14,  ///< this field is suggested to be used as output field
};

/**
 * @brief Information about field using in a filter or in a formatter
 */
struct filtercheck_field_info {
	ppm_param_type m_type = ppm_param_type::PT_NONE;  ///< Field type.
	uint32_t m_flags = 0;                             ///< Field flags.
	ppm_print_format m_print_format =
	        ppm_print_format::PF_NA;  ///< If this is a numeric field, this flag specifies if it
	                                  ///< should be rendered as octal, decimal or hex.
	std::string m_name;               ///< Field name.
	std::string m_display;            ///< Field display name (short description). May be empty.
	std::string m_description;        ///< Field description.

	//
	// Return true if this field must have an argument
	//
	inline bool is_arg_required() const { return m_flags & EPF_ARG_REQUIRED; }

	//
	// Return true if this field can optionally have an argument
	//
	inline bool is_arg_allowed() const { return m_flags & EPF_ARG_REQUIRED; }

	//
	// Returns true if this field can have an argument, either
	// optionally or mandatorily
	//
	inline bool is_arg_supported() const {
		return (m_flags & EPF_ARG_REQUIRED) || (m_flags & EPF_ARG_ALLOWED);
	}

	//
	// Returns true if this field is a list of values
	//
	inline bool is_list() const { return m_flags & EPF_IS_LIST; }

	//
	// Returns true if this filter check can support a rhs filter check instead of a const value.
	//
	inline bool is_rhs_field_supported() const { return !(m_flags & EPF_NO_RHS); }

	//
	// Returns true if this filter check can support an extraction transformer on it.
	//
	inline bool is_transformer_supported() const { return !(m_flags & EPF_NO_TRANSFORMER); }

	//
	// Return true if this field extracts unstable data pointers that may change
	// at subsequent extractions (even of other fields), thus not being safe to
	// be used with caches or field-to-field filter comparisons, unless protected
	// through a memory buffer copy (e.g. with a FTR_STORAGE transformer)
	//
	inline bool is_ptr_unstable() const { return m_flags & EPF_NO_PTR_STABILITY; }

	//
	// Returns true if this field is a suggested as output
	//
	inline bool is_format_suggested() const { return m_flags & EPF_FORMAT_SUGGESTED; }
};

/**
 * @brief Information about a group of filter/formatting fields.
 */
class filter_check_info {
public:
	enum flags : uint8_t {
		FL_NONE = 0,
		FL_HIDDEN =
		        (1 << 0),  ///< This filter check class won't be shown by fields/filter listings.
	};

	std::string m_name;       ///< Field class name.
	std::string m_shortdesc;  ///< short (< 10 words) description of this filtercheck. Can be blank.
	std::string m_desc;       ///< Field class description.
	int32_t m_nfields = 0;    ///< Number of fields in this field group.
	const filtercheck_field_info* m_fields =
	        nullptr;  ///< Array containing m_nfields field descriptions.
	uint32_t m_flags = flags::FL_NONE;
};

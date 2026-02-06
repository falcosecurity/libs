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

#include <libsinsp/state/table_entry.h>
#include <libsinsp/state/type_info.h>

#include <string>
#include <unordered_map>
#include <memory>
#include <cstring>
#include <vector>

namespace libsinsp::state {

class extensible_struct;
class dynamic_field_accessor;

/**
 * @brief Info about a given field in a dynamic struct.
 */
class dynamic_field_info {
public:
	inline dynamic_field_info(const std::string& n,
	                          size_t in,
	                          ss_plugin_state_type t,
	                          uintptr_t defsptr,
	                          bool r):
	        m_readonly(r),
	        m_index(in),
	        m_name(n),
	        m_type_id(t),
	        m_defs_id(defsptr) {}

	friend inline bool operator==(const dynamic_field_info& a, const dynamic_field_info& b) {
		return a.type_id() == b.type_id() && a.name() == b.name() && a.m_index == b.m_index &&
		       a.m_defs_id == b.m_defs_id;
	};

	friend inline bool operator!=(const dynamic_field_info& a, const dynamic_field_info& b) {
		return !(a == b);
	};

	/**
	 * @brief Returns the id of the shared definitions this info belongs to.
	 */
	inline uintptr_t defs_id() const { return m_defs_id; }

	/**
	 * @brief Returns true if the field is read only.
	 */
	inline bool readonly() const { return m_readonly; }

	/**
	 * @brief Returns true if the field info is valid.
	 */
	inline bool valid() const {
		// note(jasondellaluce): for now dynamic fields of type table are
		// not supported, so we consider them to be invalid
		return m_index != (size_t)-1 && m_type_id != SS_PLUGIN_ST_TABLE;
	}

	/**
	 * @brief Returns the name of the field.
	 */
	inline const std::string& name() const { return m_name; }

	/**
	 * @brief Returns the index of the field.
	 */
	inline size_t index() const { return m_index; }

	/**
	 * @brief Returns the type info of the field.
	 */
	inline ss_plugin_state_type type_id() const { return m_type_id; }

	/**
	 * @brief Returns a strongly-typed accessor for the given field,
	 * that can be used to reading and writing the field's value in
	 * all instances of structs where it is defined.
	 */
	inline accessor::ptr new_accessor() const;

private:
	bool m_readonly;
	size_t m_index;
	std::string m_name;
	ss_plugin_state_type m_type_id;
	uintptr_t m_defs_id;

	friend class extensible_struct;
};

/**
 * @brief Dynamic fields metadata of a given struct or class
 * that are discoverable and accessible dynamically at runtime.
 * All instances of the same struct or class must share the same
 * instance of field_infos.
 */
class dynamic_field_infos {
public:
	inline dynamic_field_infos(): m_defs_id((uintptr_t)this) {};
	inline explicit dynamic_field_infos(uintptr_t defs_id): m_defs_id(defs_id) {};
	virtual ~dynamic_field_infos() = default;
	inline dynamic_field_infos(dynamic_field_infos&&) = default;
	inline dynamic_field_infos& operator=(dynamic_field_infos&&) = default;
	inline dynamic_field_infos(const dynamic_field_infos& s) = delete;
	inline dynamic_field_infos& operator=(const dynamic_field_infos& s) = delete;

	inline uintptr_t id() const { return m_defs_id; }

	/**
	 * @brief Adds metadata for a new field to the list. An exception is
	 * thrown if two fields are defined with the same name and with
	 * incompatible types, otherwise the previous definition is returned.
	 *
	 * @param name Display name of the field.
	 * @param type_id Type of the field.
	 */
	inline const dynamic_field_info& add_field(const std::string& name,
	                                           ss_plugin_state_type type_id) {
		auto field = dynamic_field_info(name, m_definitions.size(), type_id, id(), false);
		return add_field_info(field);
	}

	virtual const std::unordered_map<std::string, dynamic_field_info>& fields() {
		return m_definitions;
	}

protected:
	virtual const dynamic_field_info& add_field_info(const dynamic_field_info& field) {
		if(field.type_id() == SS_PLUGIN_ST_TABLE) {
			throw sinsp_exception("dynamic fields of type table are not supported");
		}

		const auto& it = m_definitions.find(field.name());
		if(it != m_definitions.end()) {
			const auto& t = field.type_id();
			if(it->second.type_id() != t) {
				auto prevtype = typeinfo::from(it->second.type_id()).name();
				auto newtype = typeinfo::from(t).name();
				throw sinsp_exception(
				        "multiple definitions of dynamic field with different types in "
				        "struct: " +
				        field.name() + ", prevtype=" + prevtype + ", newtype=" + newtype);
			}
			return it->second;
		}
		m_definitions.insert({field.name(), field});
		const auto& def = m_definitions.at(field.name());
		m_definitions_ordered.push_back(&def);
		return def;
	}

	uintptr_t m_defs_id;
	std::unordered_map<std::string, dynamic_field_info> m_definitions;
	std::vector<const dynamic_field_info*> m_definitions_ordered;
	friend class extensible_struct;
};

/**
 * @brief An accessor for accessing a field of a dynamic struct.
 */
class dynamic_field_accessor : public accessor {
public:
	/**
	 * @brief Returns the info about the field to which this accessor is tied.
	 */
	inline const dynamic_field_info& info() const { return m_info; }

	inline explicit dynamic_field_accessor(const dynamic_field_info& info):
	        accessor(info.type_id()),
	        m_info(info) {};

private:
	dynamic_field_info m_info;
};

/**
 * @brief Returns a strongly-typed accessor for the given field,
 * that can be used to reading and writing the field's value in
 * all instances of structs where it is defined.
 */
inline accessor::ptr dynamic_field_info::new_accessor() const {
	if(!valid()) {
		throw sinsp_exception("can't create dynamic struct field accessor for invalid field");
	}
	return accessor::ptr(std::make_unique<dynamic_field_accessor>(*this));
}

};  // namespace libsinsp::state

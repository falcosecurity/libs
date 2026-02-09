// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2026 The Falco Authors.

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

#include <libsinsp/state/dynamic_struct.h>
#include <libsinsp/state/static_struct.h>

namespace libsinsp::state {
class extensible_struct : public table_entry {
public:
	explicit extensible_struct(
	        const std::shared_ptr<dynamic_field_infos>& dynamic_fields = nullptr):
	        m_dynamic_fields(dynamic_fields) {}

	inline extensible_struct(extensible_struct&&) = default;
	inline extensible_struct(const extensible_struct& s) { deep_fields_copy(s); }
	inline extensible_struct& operator=(extensible_struct&&) = default;
	inline extensible_struct& operator=(const extensible_struct& s) {
		if(this == &s) {
			return *this;
		}
		deep_fields_copy(s);
		return *this;
	}

	// dynamic_struct interface

	/**
	 * @brief Sets the shared definitions for the dynamic fields accessible in a struct.
	 * The definitions can be set to a non-null value only once, either at
	 * construction time by invoking this method.
	 */
	virtual void set_dynamic_fields(const std::shared_ptr<dynamic_field_infos>& defs) {
		if(m_dynamic_fields.get() == defs.get()) {
			return;
		}
		if(m_dynamic_fields && m_dynamic_fields.use_count() > 1) {
			throw sinsp_exception("dynamic struct defintions set twice");
		}
		if(!defs) {
			throw sinsp_exception("dynamic struct constructed with null field definitions");
		}
		m_dynamic_fields = defs;
	}

protected:
	/**
	 * @brief Returns information about all the dynamic fields accessible in a struct.
	 */
	inline const std::shared_ptr<dynamic_field_infos>& dynamic_fields() const {
		return m_dynamic_fields;
	}

private:
	inline dynamic_field_value* _access_dynamic_field_for_write(size_t index) {
		if(!m_dynamic_fields) {
			throw sinsp_exception("dynamic struct has no field definitions");
		}
		if(index >= m_dynamic_fields->m_definitions_ordered.size()) {
			throw sinsp_exception("dynamic struct access overflow: " + std::to_string(index));
		}
		while(m_fields.size() <= index) {
			auto def = m_dynamic_fields->m_definitions_ordered[m_fields.size()];
			m_fields.emplace_back(def->type_id());
		}
		return &m_fields[index];
	}

	inline const dynamic_field_value* _access_dynamic_field_for_read(size_t index) const {
		if(!m_dynamic_fields) {
			throw sinsp_exception("dynamic struct has no field definitions");
		}
		if(index >= m_dynamic_fields->m_definitions_ordered.size()) {
			throw sinsp_exception("dynamic struct access overflow: " + std::to_string(index));
		}
		if(m_fields.size() <= index) {
			return nullptr;
		}
		return &m_fields[index];
	}

	struct cloner {
		extensible_struct* self;
		const extensible_struct* other;
		size_t index;

		template<typename T>
		void operator()() const {
			auto ptr = self->_access_dynamic_field_for_write(index);
			auto val = other->_access_dynamic_field_for_read(index);
			*ptr = *val;
		}
	};

	inline void deep_fields_copy(const extensible_struct& other_const) {
		// note: const cast should be safe here as we're not going to resize
		// nor edit the dynamic fields allocated in "other"
		auto& other = const_cast<extensible_struct&>(other_const);

		// copy the definitions
		set_dynamic_fields(other.dynamic_fields());

		// deep copy of all the fields
		m_fields.clear();
		for(size_t i = 0; i < other.m_fields.size(); i++) {
			const auto info = m_dynamic_fields->m_definitions_ordered[i];
			dispatch_lambda(info->type_id(), cloner{this, &other, i});
		}
	}

	std::vector<dynamic_field_value> m_fields;
	std::shared_ptr<dynamic_field_infos> m_dynamic_fields;
	// end of dynamic_struct interface

protected:
	template<typename T>
	friend borrowed_state_data read_dynamic_field(const void* obj, size_t index);

	template<typename T>
	friend void write_dynamic_field(void* obj, size_t index, const borrowed_state_data& in);
};

/**
 * @brief A group of field infos, describing all the ones available
 * in a static struct.
 */
using static_field_infos = std::unordered_map<std::string, static_field_info>;

/**
 * @brief Defines the information about a field defined in the class or struct.
 * An exception is thrown if two fields are defined with the same name.
 *
 * @tparam T Type of the field.
 * @param fields Fields group to which to add the new field.
 * @param name Display name of the field.
 * @param reader Function to read the field's value from an instance of the class/struct.
 * @param readonly Read-only field annotation.
 */
template<typename T>
constexpr static const static_field_info& define_static_field(static_field_infos& fields,
                                                              const std::string& name,
                                                              accessor::reader_fn reader,
                                                              accessor::writer_fn writer,
                                                              const bool readonly = false) {
	const auto& it = fields.find(name);
	if(it != fields.end()) {
		throw sinsp_exception("multiple definitions of static field in struct: " + name);
	}

	fields.insert({name, static_field_info(name, type_id_of<T>(), readonly, reader, writer)});
	return fields.at(name);
}

}  // namespace libsinsp::state

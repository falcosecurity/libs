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

#include <libsinsp/state/borrowed_state_data.h>
#include <libsinsp/state/table_entry.h>
#include <libsinsp/state/type_info.h>

#include <string>
#include <unordered_map>
#include <memory>
#include <cstring>
#include <vector>

namespace libsinsp::state {

struct dynamic_field_value {
	ss_plugin_state_type m_type;
	ss_plugin_state_data m_data;

	explicit dynamic_field_value(ss_plugin_state_type type): m_type(type), m_data{} {
		memset(&m_data, 0, sizeof(m_data));
	}

	void update(const borrowed_state_data& val) {
		clear();
		set(val);
	}

	dynamic_field_value(const dynamic_field_value& rhs) noexcept: m_type(rhs.m_type), m_data{} {
		*this = rhs;
	}

	dynamic_field_value& operator=(const dynamic_field_value& rhs) {
		clear();
		m_type = rhs.m_type;
		set(borrowed_state_data(rhs.m_data));
		return *this;
	}

	dynamic_field_value(dynamic_field_value&& rhs) noexcept: m_type(rhs.m_type), m_data{} {
		*this = std::move(rhs);
	}

	dynamic_field_value& operator=(dynamic_field_value&& rhs) noexcept {
		m_type = rhs.m_type;
		m_data = rhs.m_data;
		rhs.m_type = static_cast<ss_plugin_state_type>(0);  // invalid type
		return *this;
	}

	~dynamic_field_value() {
		if(m_type == SS_PLUGIN_ST_STRING) {
			free(const_cast<char*>(m_data.str));
		}
	}

private:
	void clear() {
		if(m_type == SS_PLUGIN_ST_STRING) {
			free(const_cast<char*>(m_data.str));
			m_data.str = nullptr;
		}
	}

	void set(const libsinsp::state::borrowed_state_data& val) {
		if(m_type == SS_PLUGIN_ST_STRING) {
			m_data.str = strdup(val.data().str);
		} else {
			m_data = val.data();
		}
	}
};

class extensible_struct;

template<typename T>
borrowed_state_data read_dynamic_field(const void* obj, size_t index) {
	auto dstruct = static_cast<const T*>(obj);
	if(auto ptr = dstruct->_access_dynamic_field_for_read(index)) {
		return borrowed_state_data(ptr->m_data);
	}
	return {};
}

template<typename T>
void write_dynamic_field(void* obj, size_t index, const libsinsp::state::borrowed_state_data& in) {
	auto dstruct = static_cast<T*>(obj);
	auto ptr = dstruct->_access_dynamic_field_for_write(index);
	ptr->update(in);
}

/**
 * @brief Dynamic fields metadata of a given struct or class
 * that are discoverable and accessible dynamically at runtime.
 * All instances of the same struct or class must share the same
 * instance of field_infos.
 */
class dynamic_field_infos {
public:
	inline dynamic_field_infos(accessor::reader_fn reader, accessor::writer_fn writer):
	        m_reader(reader),
	        m_writer(writer) {};
	virtual ~dynamic_field_infos() = default;
	inline dynamic_field_infos(dynamic_field_infos&&) = default;
	inline dynamic_field_infos& operator=(dynamic_field_infos&&) = default;
	inline dynamic_field_infos(const dynamic_field_infos& s) = delete;
	inline dynamic_field_infos& operator=(const dynamic_field_infos& s) = delete;

	template<typename T>
	static std::shared_ptr<dynamic_field_infos> make() {
		return std::make_shared<dynamic_field_infos>(read_dynamic_field<T>, write_dynamic_field<T>);
	}

	/**
	 * @brief Adds metadata for a new field to the list. An exception is
	 * thrown if two fields are defined with the same name and with
	 * incompatible types, otherwise the previous definition is returned.
	 *
	 * @param name Display name of the field.
	 * @param type_id Type of the field.
	 */
	inline const accessor& add_field(const std::string& name, ss_plugin_state_type type_id) {
		auto field = accessor(name, type_id, m_reader, m_writer, m_definitions.size(), false);
		return add_field_info(field);
	}

	virtual const std::unordered_map<std::string, accessor>& fields() { return m_definitions; }

protected:
	virtual const accessor& add_field_info(const accessor& field) {
		if(field.type_id() == SS_PLUGIN_ST_TABLE) {
			throw sinsp_exception("dynamic fields of type table are not supported");
		}

		const auto& it = m_definitions.find(field.name());
		if(it != m_definitions.end()) {
			const auto& t = field.type_id();
			if(it->second.type_id() != t) {
				auto prevtype = type_name(it->second.type_id());
				auto newtype = type_name(t);
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

	std::unordered_map<std::string, accessor> m_definitions;
	std::vector<const accessor*> m_definitions_ordered;
	accessor::reader_fn m_reader;
	accessor::writer_fn m_writer;

	friend class extensible_struct;
};

};  // namespace libsinsp::state

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
#include <libsinsp/state/plugin_statetype_switch.h>
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

/**
 * @brief A base class for classes and structs that allow dynamic programming
 * by being extensible and allowing adding and accessing new data fields at runtime.
 */
class dynamic_struct : virtual public table_entry {
public:
	class field_accessor;

	/**
	 * @brief Info about a given field in a dynamic struct.
	 */
	class field_info {
	public:
		inline field_info(const std::string& n,
		                  size_t in,
		                  ss_plugin_state_type t,
		                  uintptr_t defsptr,
		                  bool r = false):
		        m_readonly(r),
		        m_index(in),
		        m_name(n),
		        m_type_id(t),
		        m_defs_id(defsptr) {}

		friend inline bool operator==(const field_info& a, const field_info& b) {
			return a.type_id() == b.type_id() && a.name() == b.name() && a.m_index == b.m_index &&
			       a.m_defs_id == b.m_defs_id;
		};

		friend inline bool operator!=(const field_info& a, const field_info& b) {
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
		inline accessor::ptr new_accessor() const {
			if(!valid()) {
				throw sinsp_exception(
				        "can't create dynamic struct field accessor for invalid field");
			}
			return accessor::ptr(std::make_unique<field_accessor>(*this));
		}

	private:
		bool m_readonly;
		size_t m_index;
		std::string m_name;
		ss_plugin_state_type m_type_id;
		uintptr_t m_defs_id;

		friend class dynamic_struct;
	};
	class field_infos {
	public:
		inline field_infos(): m_defs_id((uintptr_t)this) {};
		inline explicit field_infos(uintptr_t defs_id): m_defs_id(defs_id) {};
		virtual ~field_infos() = default;
		inline field_infos(field_infos&&) = default;
		inline field_infos& operator=(field_infos&&) = default;
		inline field_infos(const field_infos& s) = delete;
		inline field_infos& operator=(const field_infos& s) = delete;

		inline uintptr_t id() const { return m_defs_id; }

		/**
		 * @brief Adds metadata for a new field to the list. An exception is
		 * thrown if two fields are defined with the same name and with
		 * incompatible types, otherwise the previous definition is returned.
		 *
		 * @param name Display name of the field.
		 * @param type_id Type of the field.
		 */
		inline const field_info& add_field(const std::string& name, ss_plugin_state_type type_id) {
			auto field = field_info(name, m_definitions.size(), type_id, id());
			return add_field_info(field);
		}

		virtual const std::unordered_map<std::string, field_info>& fields() {
			return m_definitions;
		}

	protected:
		virtual const field_info& add_field_info(const field_info& field) {
			if(field.type_id() == SS_PLUGIN_ST_TABLE) {
				throw sinsp_exception("dynamic fields of type table are not supported");
			}

			const auto& it = m_definitions.find(field.name());
			if(it != m_definitions.end()) {
				const auto t = field.type_id();
				if(it->second.type_id() != t) {
					std::string prevtype = type_name(it->second.type_id());
					std::string newtype = type_name(t);
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
		std::unordered_map<std::string, field_info> m_definitions;
		std::vector<const field_info*> m_definitions_ordered;
		friend class dynamic_struct;
	};

	/**
	 * @brief An strongly-typed accessor for accessing a field of a dynamic struct.
	 * @tparam T Type of the field.
	 */
	class field_accessor : public accessor {
	public:
		/**
		 * @brief Returns the info about the field to which this accessor is tied.
		 */
		inline const field_info& info() const { return m_info; }

		inline explicit field_accessor(const field_info& info):
		        accessor(info.m_type_id),
		        m_info(info) {};

	private:
		field_info m_info;

		friend class dynamic_struct;
		friend class dynamic_struct::field_info;
	};

	/**
	 * @brief Dynamic fields metadata of a given struct or class
	 * that are discoverable and accessible dynamically at runtime.
	 * All instances of the same struct or class must share the same
	 * instance of field_infos.
	 */

	inline explicit dynamic_struct(const std::shared_ptr<field_infos>& dynamic_fields):
	        m_fields(),
	        m_dynamic_fields(dynamic_fields) {}

	inline dynamic_struct(dynamic_struct&&) = default;

	inline dynamic_struct(const dynamic_struct& s) { deep_fields_copy(s); }

	inline dynamic_struct& operator=(dynamic_struct&&) = default;

	inline dynamic_struct& operator=(const dynamic_struct& s) {
		if(this == &s) {
			return *this;
		}
		deep_fields_copy(s);
		return *this;
	}
	inline const std::shared_ptr<field_infos>& dynamic_fields() const { return m_dynamic_fields; }

	virtual ~dynamic_struct() { dynamic_struct::destroy_dynamic_fields(); }

	/**
	 * @brief Returns information about all the dynamic fields accessible in a struct.
	 */

	/**
	 * @brief Sets the shared definitions for the dynamic fields accessible in a struct.
	 * The definitions can be set to a non-null value only once, either at
	 * construction time by invoking this method.
	 */
	virtual void set_dynamic_fields(const std::shared_ptr<field_infos>& defs) {
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
	 * @brief Destroys all the dynamic field values currently allocated
	 */
	virtual void destroy_dynamic_fields() { m_fields.clear(); }

	[[nodiscard]] const void* raw_read_field(const accessor& a) const override {
		thread_local std::string str;
		auto acc = dynamic_cast<const field_accessor*>(&a);
		_check_defsptr(acc->info(), false);
		auto ptr = _access_dynamic_field_for_read(acc->info().index());
		if(ptr) {
			if(a.type_info() == SS_PLUGIN_ST_STRING) {
				str = ptr->m_data.str;
				return &str;
			}
#define _X(ty, field) return &ptr->m_data.field;
			__PLUGIN_STATETYPE_SWITCH(a.type_info());
#undef _X
		}
		return nullptr;
	}

	void raw_write_field(const accessor& a, const void* in) override {
		auto acc = dynamic_cast<const field_accessor*>(&a);
		_check_defsptr(acc->info(), true);
		if(acc->info().readonly()) {
			throw sinsp_exception("can't set a read-only dynamic struct field: " +
			                      acc->info().name());
		}
		auto writer = [&]<typename T>() {
			auto val = static_cast<const T*>(in);
			auto ptr = _access_dynamic_field_for_write(acc->info().index());
			ptr->update(borrowed_state_data::from<type_id_of<T>(), T>(*val));
		};
		return dispatch_lambda(a.type_info(), writer);
	}

private:
	inline void _check_defsptr(const field_info& i, bool write) const {
		if(!i.valid()) {
			throw sinsp_exception("can't set invalid field in dynamic struct");
		}
		if(m_dynamic_fields->id() != i.m_defs_id) {
			throw sinsp_exception(
			        "using dynamic field accessor on struct it was not created from: " + i.name());
		}
		if(write && i.readonly()) {
			throw sinsp_exception("can't set a read-only dynamic struct field: " + i.name());
		}
	}

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

	inline void deep_fields_copy(const dynamic_struct& other_const) {
		// note: const cast should be safe here as we're not going to resize
		// nor edit the dynamic fields allocated in "other"
		auto& other = const_cast<dynamic_struct&>(other_const);

		// copy the definitions
		set_dynamic_fields(other.dynamic_fields());

		auto clone_from = [&]<typename T>(const field_info& fi, const dynamic_struct& src) {
			auto src_ptr = src._access_dynamic_field_for_read(fi.index());
			auto dst_ptr = _access_dynamic_field_for_write(fi.index());
			*dst_ptr = *src_ptr;
		};

		// deep copy of all the fields
		destroy_dynamic_fields();
		for(size_t i = 0; i < other.m_fields.size(); i++) {
			const auto info = m_dynamic_fields->m_definitions_ordered[i];
			dispatch_lambda(info->m_type_id, clone_from, *info, other_const);
		}
	}

	std::vector<dynamic_field_value> m_fields;
	std::shared_ptr<field_infos> m_dynamic_fields;
};

class dynamic_table_fields : virtual public table_fields {
public:
	explicit dynamic_table_fields(
	        const std::shared_ptr<dynamic_struct::field_infos>& dynamic_fields = nullptr):
	        m_dynamic_fields(dynamic_fields != nullptr
	                                 ? dynamic_fields
	                                 : std::make_shared<dynamic_struct::field_infos>()) {}

	void list_fields(std::vector<ss_plugin_table_fieldinfo>& out) const override {
		for(auto& info : this->dynamic_fields()->fields()) {
			ss_plugin_table_fieldinfo i;
			i.name = info.second.name().c_str();
			i.field_type = info.second.type_id();
			i.read_only = false;
			out.push_back(i);
		}
	}

	using table_fields::get_field;
	accessor::ptr get_field(const char* name, ss_plugin_state_type type_id) override {
		auto dyn_it = this->dynamic_fields()->fields().find(name);

		if(dyn_it != this->dynamic_fields()->fields().end()) {
			if(type_id != dyn_it->second.type_id()) {
				throw sinsp_exception("incompatible data types for dynamic field: " +
				                      std::string(name));
			}
			return dyn_it->second.new_accessor();
		}
		return libsinsp::state::accessor::null();  // field not found
	}

	using table_fields::add_field;
	accessor::ptr add_field(const char* name, ss_plugin_state_type type_id) override {
		this->dynamic_fields()->add_field(name, type_id);
		return get_field(name, type_id);
	}

	virtual void set_dynamic_fields(const std::shared_ptr<dynamic_struct::field_infos>& dynf) {
		if(m_dynamic_fields.get() == dynf.get()) {
			return;
		}
		if(!dynf) {
			throw sinsp_exception("null definitions passed to set_dynamic_fields");
		}
		if(m_dynamic_fields && m_dynamic_fields.use_count() > 1) {
			throw sinsp_exception("can't replace already in-use dynamic fields table definitions");
		}
		m_dynamic_fields = dynf;
	}

protected:
	/**
	 * @brief Returns the fields metadata list for the dynamic fields defined
	 * for the value data type of this table. This fields will be accessible
	 * for all the entries of this table. The returned metadata list can
	 * be expended at runtime by adding new dynamic fields, which will then
	 * be allocated and accessible for all the present and future entries
	 * present in the table.
	 */
	[[nodiscard]] const std::shared_ptr<dynamic_struct::field_infos>& dynamic_fields() const {
		return m_dynamic_fields;
	}

private:
	std::shared_ptr<dynamic_struct::field_infos> m_dynamic_fields;
};

};  // namespace libsinsp::state

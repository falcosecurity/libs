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

namespace libsinsp {
namespace state {

/**
 * @brief A base class for classes and structs that allow dynamic programming
 * by making part (or all) of their fields discoverable and accessible at runtime.
 * The structure of the class is predetermined at compile-time and its fields
 * are placed at a given offset within the class memory area.
 */
class static_struct : virtual public table_entry {
public:
	/**
	 * @brief Info about a given field in a static struct.
	 */
	class field_info {
	public:
		friend inline bool operator==(const field_info& a, const field_info& b) {
			return a.info() == b.info() && a.name() == b.name() && a.readonly() == b.readonly() &&
			       a.m_offset == b.m_offset;
		};

		friend inline bool operator!=(const field_info& a, const field_info& b) {
			return !(a == b);
		};

		/**
		 * @brief Returns true if the field info is valid.
		 */
		inline bool valid() const { return m_offset != (size_t)-1; }

		/**
		 * @brief Returns true if the field is read only.
		 */
		inline bool readonly() const { return m_readonly; }

		/**
		 * @brief Returns the name of the field.
		 */
		inline const std::string& name() const { return m_name; }

		/**
		 * @brief Returns the type info of the field.
		 */
		inline ss_plugin_state_type info() const { return m_type_id; }

		/**
		 * @brief Returns a strongly-typed accessor for the given field,
		 * that can be used to reading and writing the field's value in
		 * all instances of structs where it is defined.
		 */
		inline accessor::ptr new_accessor() const {
			if(!valid()) {
				throw sinsp_exception(
				        "can't create static struct field accessor for invalid field");
			}
			return accessor::ptr(std::make_unique<field_accessor>(*this));
		}

	private:
		inline field_info(const std::string& n, size_t o, ss_plugin_state_type t, bool r):
		        m_readonly(r),
		        m_offset(o),
		        m_name(n),
		        m_type_id(t) {}

		bool m_readonly;
		size_t m_offset;
		std::string m_name;
		ss_plugin_state_type m_type_id;

		friend class static_struct;
	};

	/**
	 * @brief An strongly-typed accessor for accessing a field of a static struct.
	 * @tparam T Type of the field.
	 */
	class field_accessor : public accessor {
	public:
		/**
		 * @brief Returns the info about the field to which this accessor is tied.
		 */
		[[nodiscard]] const field_info& info() const { return m_info; }

		explicit field_accessor(field_info info):
		        accessor(info.m_type_id),
		        m_info(std::move(info)) {};

	private:
		field_info m_info;

		friend class static_struct;
	};

	/**
	 * @brief A group of field infos, describing all the ones available
	 * in a static struct.
	 */
	using field_infos = std::unordered_map<std::string, field_info>;

protected:
	/**
	 * @brief Defines the information about a field defined in the class or struct.
	 * An exception is thrown if two fields are defined with the same name.
	 *
	 * @tparam T Type of the field.
	 * @param fields Fields group to which to add the new field.
	 * @param offset Field's memory offset in instances of the class/struct.
	 * @param name Display name of the field.
	 * @param readonly Read-only field annotation.
	 */
	template<typename T>
	constexpr static const field_info& define_static_field(field_infos& fields,
	                                                       const size_t offset,
	                                                       const std::string& name,
	                                                       const bool readonly = false) {
		const auto& it = fields.find(name);
		if(it != fields.end()) {
			throw sinsp_exception("multiple definitions of static field in struct: " + name);
		}

		// todo(jasondellaluce): add extra safety boundary checks here
		fields.insert({name, field_info(name, offset, type_id_of<T>(), readonly)});
		return fields.at(name);
	}

	[[nodiscard]] borrowed_state_data raw_read_field(const accessor& a) const override {
		auto acc = dynamic_cast<const field_accessor*>(&a);
		if(!acc->info().valid()) {
			throw sinsp_exception("can't get invalid field in static struct");
		}
		auto reader = [&]<typename T>() {
			const T* ptr = reinterpret_cast<const T*>(reinterpret_cast<const char*>(this) +
			                                          acc->info().m_offset);

			return borrowed_state_data::from<type_id_of<T>(), T>(*ptr);
		};
		return dispatch_lambda(a.type_info(), reader);
	}

	void raw_write_field(const accessor& a, const void* in) override {
		auto acc = dynamic_cast<const field_accessor*>(&a);
		if(!acc->info().valid()) {
			throw sinsp_exception("can't set invalid field in static struct");
		}
		if(acc->info().readonly()) {
			throw sinsp_exception("can't set a read-only static struct field: " +
			                      acc->info().name());
		}
		auto writer = [&]<typename T>() {
			auto val = static_cast<const T*>(in);
			*reinterpret_cast<T*>(reinterpret_cast<char*>(this) + acc->info().m_offset) = *val;
		};
		return dispatch_lambda(a.type_info(), writer);
	}
};

class static_table_fields : virtual public table_fields {
public:
	explicit static_table_fields(const static_struct::field_infos* const m_static_fields):
	        m_static_fields(m_static_fields) {}

	using table_fields::list_fields;
	void list_fields(std::vector<ss_plugin_table_fieldinfo>& out) const override;

	using table_fields::get_field;
	accessor::ptr get_field(const char* name, ss_plugin_state_type type_id) override;

	using table_fields::add_field;
	accessor::ptr add_field(const char* name, ss_plugin_state_type type_id) override;

private:
	const static_struct::field_infos* const m_static_fields;
};

};  // namespace state
};  // namespace libsinsp

// This `offsetof` custom definition prevents the compiler from complaining about "offsetof"-ing on
// non-standard-layout types (e.g.: `warning: ‘offsetof’ within non-standard-layout type ‘X’ is
// conditionally-supported)`.
#define OFFSETOF_STATIC_FIELD(type, member) reinterpret_cast<size_t>(&static_cast<type*>(0)->member)

// DEFINE_STATIC_FIELD macro is a wrapper around static_struct::define_static_field helping to
// extract the field type and field offset.
#define DEFINE_STATIC_FIELD(field_infos, container_type, container_field, name)      \
	define_static_field<decltype(static_cast<container_type*>(0)->container_field)>( \
	        field_infos,                                                             \
	        OFFSETOF_STATIC_FIELD(container_type, container_field),                  \
	        name);

// DEFINE_STATIC_FIELD_READONLY macro is a wrapper around static_struct::define_static_field helping
// to extract the field type and field offset. The defined field is set to guarantee read-only
// access.
#define DEFINE_STATIC_FIELD_READONLY(field_infos, container_type, container_field, name) \
	define_static_field<decltype(static_cast<container_type*>(0)->container_field)>(     \
	        field_infos,                                                                 \
	        OFFSETOF_STATIC_FIELD(container_type, container_field),                      \
	        name,                                                                        \
	        true);

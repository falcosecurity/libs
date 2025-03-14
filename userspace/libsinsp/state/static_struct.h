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
class static_struct {
public:
	template<typename T>
	class field_accessor;

	/**
	 * @brief Info about a given field in a static struct.
	 */
	class field_info {
	public:
		inline field_info():
		        m_readonly(true),
		        m_offset((size_t)-1),
		        m_name(""),
		        m_info(typeinfo::of<uint8_t>()) {}
		inline ~field_info() = default;
		inline field_info(field_info&&) = default;
		inline field_info& operator=(field_info&&) = default;
		inline field_info(const field_info& s) = default;
		inline field_info& operator=(const field_info& s) = default;

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
		inline const libsinsp::state::typeinfo& info() const { return m_info; }

		/**
		 * @brief Returns a strongly-typed accessor for the given field,
		 * that can be used to reading and writing the field's value in
		 * all instances of structs where it is defined.
		 */
		template<typename T>
		inline field_accessor<T> new_accessor() const {
			if(!valid()) {
				throw sinsp_exception(
				        "can't create static struct field accessor for invalid field");
			}
			auto t = libsinsp::state::typeinfo::of<T>();
			if(m_info != t) {
				throw sinsp_exception(
				        "incompatible type for static struct field accessor: field=" + m_name +
				        ", expected_type=" + t.name() + ", actual_type=" + m_info.name());
			}
			return field_accessor<T>(*this);
		}

	private:
		inline field_info(const std::string& n, size_t o, const typeinfo& i, bool r):
		        m_readonly(r),
		        m_offset(o),
		        m_name(n),
		        m_info(i) {}

		template<typename T>
		static inline field_info _build(const std::string& name,
		                                size_t offset,
		                                bool readonly = false) {
			return field_info(name, offset, libsinsp::state::typeinfo::of<T>(), readonly);
		}

		bool m_readonly;
		size_t m_offset;
		std::string m_name;
		libsinsp::state::typeinfo m_info;

		friend class static_struct;
	};

	/**
	 * @brief An strongly-typed accessor for accessing a field of a static struct.
	 * @tparam T Type of the field.
	 */
	template<typename T>
	class field_accessor {
	public:
		inline field_accessor() = default;
		inline ~field_accessor() = default;
		inline field_accessor(field_accessor&&) = default;
		inline field_accessor& operator=(field_accessor&&) = default;
		inline field_accessor(const field_accessor& s) = default;
		inline field_accessor& operator=(const field_accessor& s) = default;

		/**
		 * @brief Returns the info about the field to which this accessor is tied.
		 */
		inline const field_info& info() const { return m_info; }

	private:
		field_accessor(const field_info& info): m_info(info) {};

		field_info m_info;

		friend class static_struct;
		friend class static_struct::field_info;
	};

	/**
	 * @brief A group of field infos, describing all the ones available
	 * in a static struct.
	 */
	using field_infos = std::unordered_map<std::string, field_info>;

	inline static_struct() = default;
	inline virtual ~static_struct() = default;
	inline static_struct(static_struct&&) = default;
	inline static_struct& operator=(static_struct&&) = default;
	inline static_struct(const static_struct& s) = default;
	inline static_struct& operator=(const static_struct& s) = default;

	/**
	 * @brief Accesses a field with the given accessor and reads its value.
	 */
	template<typename T>
	inline const T& get_static_field(const field_accessor<T>& a) const {
		if(!a.info().valid()) {
			throw sinsp_exception("can't get invalid field in static struct");
		}
		return *(reinterpret_cast<T*>((void*)(((uintptr_t)this) + a.info().m_offset)));
	}

	/**
	 * @brief Accesses a field with the given accessor and reads its value.
	 */
	template<typename T, typename Val = T>
	inline void get_static_field(const field_accessor<T>& a, Val& out) const {
		out = get_static_field<T>(a);
	}

	/**
	 * @brief Accesses a field with the given accessor and writes its value.
	 * An exception is thrown if the field is read-only.
	 */
	template<typename T, typename Val = T>
	inline void set_static_field(const field_accessor<T>& a, const Val& in) {
		if(!a.info().valid()) {
			throw sinsp_exception("can't set invalid field in static struct");
		}
		if(a.info().readonly()) {
			throw sinsp_exception("can't set a read-only static struct field: " + a.info().name());
		}
		*(reinterpret_cast<T*>((void*)(((uintptr_t)this) + a.info().m_offset))) = in;
	}

	/**
	 * @brief Returns information about all the static fields accessible in a struct.
	 */
	virtual field_infos static_fields() const { return {}; }

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
		fields.insert({name, field_info::_build<T>(name, offset, readonly)});
		return fields.at(name);
	}
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

// specializations for strings
template<>
inline void libsinsp::state::static_struct::get_static_field<std::string, const char*>(
        const field_accessor<std::string>& a,
        const char*& out) const {
	out = get_static_field<std::string>(a).c_str();
}

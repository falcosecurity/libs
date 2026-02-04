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

#include <libsinsp/state/state_struct.h>
#include <libsinsp/state/type_info.h>

#include <string>
#include <unordered_map>

namespace libsinsp {
namespace state {

template<typename T>
class static_field_accessor;

/**
 * @brief Info about a given field in a static struct.
 */
class static_field_info {
public:
	friend inline bool operator==(const static_field_info& a, const static_field_info& b) {
		return a.info() == b.info() && a.name() == b.name() && a.readonly() == b.readonly() &&
		       a.m_offset == b.m_offset;
	};

	friend inline bool operator!=(const static_field_info& a, const static_field_info& b) {
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
	 * @brief Returns the offset of the field within the struct.
	 */
	inline size_t offset() const { return m_offset; }

	/**
	 * @brief Returns a strongly-typed accessor for the given field,
	 * that can be used to reading and writing the field's value in
	 * all instances of structs where it is defined.
	 */
	template<typename T>
	inline static_field_accessor<T> new_accessor() const {
		if(!valid()) {
			throw sinsp_exception("can't create static struct field accessor for invalid field");
		}
		auto t = libsinsp::state::typeinfo::of<T>();
		if(m_info != t) {
			throw sinsp_exception(
			        "incompatible type for static struct field accessor: field=" + m_name +
			        ", expected_type=" + t.name() + ", actual_type=" + m_info.name());
		}
		return static_field_accessor<T>(*this);
	}

	inline static_field_info(const std::string& n, size_t o, const typeinfo& i, bool r):
	        m_readonly(r),
	        m_offset(o),
	        m_name(n),
	        m_info(i) {}

private:
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
class static_field_accessor : public typed_accessor<T> {
public:
	/**
	 * @brief Returns the info about the field to which this accessor is tied.
	 */
	[[nodiscard]] const static_field_info& info() const { return m_info; }

private:
	explicit static_field_accessor(static_field_info info): m_info(std::move(info)) {};

	static_field_info m_info;

	friend class static_struct;
	friend class static_field_info;
};

/**
 * @brief A base class for classes and structs that allow dynamic programming
 * by making part (or all) of their fields discoverable and accessible at runtime.
 * The structure of the class is predetermined at compile-time and its fields
 * are placed at a given offset within the class memory area.
 */
class static_struct : public state_struct {
public:
	/**
	 * @brief A group of field infos, describing all the ones available
	 * in a static struct.
	 */
	using field_infos = std::unordered_map<std::string, static_field_info>;

	/**
	 * @brief Accesses a field with the given accessor and reads its value.
	 */
	template<typename T>
	inline const T& get_static_field(const static_field_accessor<T>& a) const {
		if(!a.info().valid()) {
			throw sinsp_exception("can't get invalid field in static struct");
		}
		return *(reinterpret_cast<T*>((void*)(((uintptr_t)this) + a.info().m_offset)));
	}

	/**
	 * @brief Accesses a field with the given accessor and reads its value.
	 */
	template<typename T, typename Val = T>
	inline void get_static_field(const static_field_accessor<T>& a, Val& out) const {
		out = get_static_field<T>(a);
	}

	/**
	 * @brief Accesses a field with the given accessor and writes its value.
	 * An exception is thrown if the field is read-only.
	 */
	template<typename T, typename Val = T>
	inline void set_static_field(const static_field_accessor<T>& a, const Val& in) {
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
	struct reader {
		const static_struct* self;
		const accessor* acc;

		template<typename T>
		const void* operator()() const {
			auto field_acc = dynamic_cast<const static_field_accessor<T>*>(acc);
			if(!field_acc->info().valid()) {
				throw sinsp_exception("can't get invalid field in static struct");
			}
			return reinterpret_cast<const char*>(self) + field_acc->info().m_offset;
		}
	};

	[[nodiscard]] const void* raw_read_field(const accessor& a) const override {
		return dispatch_lambda(a.type_info().type_id(), reader{this, &a});
	}

	struct writer {
		static_struct* self;
		const accessor* acc;
		const void* in;

		template<typename T>
		void operator()() const {
			auto field_acc = dynamic_cast<const static_field_accessor<T>*>(acc);
			if(!field_acc->info().valid()) {
				throw sinsp_exception("can't set invalid field in static struct");
			}
			if(field_acc->info().readonly()) {
				throw sinsp_exception("can't set a read-only static struct field: " +
				                      field_acc->info().name());
			}
			auto ptr = reinterpret_cast<T*>(reinterpret_cast<char*>(self) +
			                                field_acc->info().m_offset);
			auto val = static_cast<const T*>(in);
			*ptr = *val;
		}
	};

	void raw_write_field(const accessor& a, const void* in) override {
		return dispatch_lambda(a.type_info().type_id(), writer{this, &a, in});
	}
};

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
constexpr static const static_field_info& define_static_field(static_struct::field_infos& fields,
                                                              const size_t offset,
                                                              const std::string& name,
                                                              const bool readonly = false) {
	const auto& it = fields.find(name);
	if(it != fields.end()) {
		throw sinsp_exception("multiple definitions of static field in struct: " + name);
	}

	// todo(jasondellaluce): add extra safety boundary checks here
	fields.insert({name, static_field_info(name, offset, typeinfo::of<T>(), readonly)});
	return fields.at(name);
}

};  // namespace state
};  // namespace libsinsp

// This `offsetof` custom definition prevents the compiler from complaining about "offsetof"-ing on
// non-standard-layout types (e.g.: `warning: ‘offsetof’ within non-standard-layout type ‘X’ is
// conditionally-supported)`.
#define OFFSETOF_STATIC_FIELD(type, member) reinterpret_cast<size_t>(&static_cast<type*>(0)->member)

// DEFINE_STATIC_FIELD macro is a wrapper around static_struct::define_static_field helping to
// extract the field type and field offset.
#define DEFINE_STATIC_FIELD(field_infos, container_type, container_field, name) \
	libsinsp::state::define_static_field<                                       \
	        decltype(static_cast<container_type*>(0)->container_field)>(        \
	        field_infos,                                                        \
	        OFFSETOF_STATIC_FIELD(container_type, container_field),             \
	        name);

// DEFINE_STATIC_FIELD_READONLY macro is a wrapper around static_struct::define_static_field helping
// to extract the field type and field offset. The defined field is set to guarantee read-only
// access.
#define DEFINE_STATIC_FIELD_READONLY(field_infos, container_type, container_field, name) \
	libsinsp::state::define_static_field<                                                \
	        decltype(static_cast<container_type*>(0)->container_field)>(                 \
	        field_infos,                                                                 \
	        OFFSETOF_STATIC_FIELD(container_type, container_field),                      \
	        name,                                                                        \
	        true);

// specializations for strings
template<>
inline void libsinsp::state::static_struct::get_static_field<std::string, const char*>(
        const static_field_accessor<std::string>& a,
        const char*& out) const {
	out = get_static_field<std::string>(a).c_str();
}

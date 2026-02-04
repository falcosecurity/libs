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
class extensible_struct : public state_struct, public dynamic_struct {
public:
	explicit extensible_struct(
	        const std::shared_ptr<dynamic_field_infos>& dynamic_fields = nullptr):
	        dynamic_struct(dynamic_fields) {}

	// static_struct interface
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
		return *(reinterpret_cast<T*>((void*)(((uintptr_t)this) + a.info().offset())));
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
		*(reinterpret_cast<T*>((void*)(((uintptr_t)this) + a.info().offset()))) = in;
	}

	/**
	 * @brief Returns information about all the static fields accessible in a struct.
	 */
	virtual field_infos static_fields() const { return {}; }
	// end of static_struct interface

protected:
	struct reader {
		const extensible_struct* self;
		const accessor* acc;

		template<typename T>
		const void* operator()() const {
			if(auto static_acc = dynamic_cast<const static_field_accessor<T>*>(acc)) {
				if(!static_acc->info().valid()) {
					throw sinsp_exception("can't get invalid field in static struct");
				}
				return reinterpret_cast<const char*>(self) + static_acc->info().offset();
			}

			if(auto dynamic_acc = dynamic_cast<const dynamic_field_accessor<T>*>(acc)) {
				self->_check_defsptr(dynamic_acc->info(), false);
				return self->_access_dynamic_field_for_read(dynamic_acc->info().index());
			}

#ifdef _MSC_VER
			_assume(0);
#else
			__builtin_unreachable();
#endif
		}
	};
	[[nodiscard]] const void* raw_read_field(const accessor& a) const override {
		return dispatch_lambda(a.type_info().type_id(), reader{this, &a});
	}

	struct writer {
		extensible_struct* self;
		const accessor* acc;
		const void* in;

		template<typename T>
		void operator()() const {
			if(auto static_acc = dynamic_cast<const static_field_accessor<T>*>(acc)) {
				if(!static_acc->info().valid()) {
					throw sinsp_exception("can't set invalid field in static struct");
				}
				if(static_acc->info().readonly()) {
					throw sinsp_exception("can't set a read-only static struct field: " +
					                      static_acc->info().name());
				}
				auto ptr = reinterpret_cast<T*>(reinterpret_cast<char*>(self) +
				                                static_acc->info().offset());
				auto val = static_cast<const T*>(in);
				*ptr = *val;
				return;
			}

			if(auto dynamic_acc = dynamic_cast<const dynamic_field_accessor<T>*>(acc)) {
				self->_check_defsptr(dynamic_acc->info(), true);
				auto ptr = static_cast<T*>(
				        self->_access_dynamic_field_for_write(dynamic_acc->info().index()));
				auto val = static_cast<const T*>(in);
				*ptr = *val;
				return;
			}

#ifdef _MSC_VER
			_assume(0);
#else
			__builtin_unreachable();
#endif
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
constexpr static const static_field_info& define_static_field(
        extensible_struct::field_infos& fields,
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

}  // namespace libsinsp::state

// specializations for strings
template<>
inline void libsinsp::state::extensible_struct::get_static_field<std::string, const char*>(
        const static_field_accessor<std::string>& a,
        const char*& out) const {
	out = get_static_field<std::string>(a).c_str();
}

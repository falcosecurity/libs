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
class extensible_struct : public state_struct {
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
	~extensible_struct() override { extensible_struct::destroy_dynamic_fields(); }

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

	// dynamic_struct interface

	inline const std::shared_ptr<dynamic_field_infos>& dynamic_fields() const {
		return m_dynamic_fields;
	}

	/**
	 * @brief Accesses a field with the given accessor and reads its value.
	 */
	template<typename T, typename Val = T>
	inline void get_dynamic_field(const dynamic_field_accessor<T>& a, Val& out) {
		_check_defsptr(a.info(), false);
		get_dynamic_field(a.info(), reinterpret_cast<void*>(&out));
	}

	/**
	 * @brief Accesses a field with the given accessor and writes its value.
	 */
	template<typename T, typename Val = T>
	inline void set_dynamic_field(const dynamic_field_accessor<T>& a, const Val& in) {
		_check_defsptr(a.info(), true);
		if(a.info().readonly()) {
			throw sinsp_exception("can't set a read-only dynamic struct field: " + a.info().name());
		}
		set_dynamic_field(a.info(), reinterpret_cast<const void*>(&in));
	}

	/**
	 * @brief Returns information about all the dynamic fields accessible in a struct.
	 */

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
	 * @brief Gets the value of a dynamic field and writes it into "out".
	 * "out" points to a variable having the type of the field_info argument,
	 * according to the type definitions supported in libsinsp::state::typeinfo.
	 * For strings, "out" is considered of type const char**.
	 */
	virtual void get_dynamic_field(const dynamic_field_info& i, void* out) {
		const auto* buf = _access_dynamic_field_for_read(i.m_index);
		if(i.info().type_id() == SS_PLUGIN_ST_STRING) {
			if(buf == nullptr) {
				*((const char**)out) = "";
			} else {
				*((const char**)out) = ((const std::string*)buf)->c_str();
			}
		} else {
			if(buf == nullptr) {
				// if the field is not set, we return a zeroed buffer
				memset(out, 0, i.info().size());
			} else {
				memcpy(out, buf, i.info().size());
			}
		}
	}

	/**
	 * @brief Sets the value of a dynamic field by reading it from "in".
	 * "in" points to a variable having the type of the field_info argument,
	 * according to the type definitions supported in libsinsp::state::typeinfo.
	 * For strings, "in" is considered of type const char**.
	 */
	virtual void set_dynamic_field(const dynamic_field_info& i, const void* in) {
		auto* buf = _access_dynamic_field_for_write(i.m_index);
		if(i.info().type_id() == SS_PLUGIN_ST_STRING) {
			*((std::string*)buf) = *((const char**)in);
		} else {
			memcpy(buf, in, i.info().size());
		}
	}

	/**
	 * @brief Destroys all the dynamic field values currently allocated
	 */
	virtual void destroy_dynamic_fields() {
		if(!m_dynamic_fields) {
			return;
		}
		for(size_t i = 0; i < m_fields.size(); i++) {
			m_dynamic_fields->m_definitions_ordered[i]->info().destroy(m_fields[i]);
			free(m_fields[i]);
		}
		m_fields.clear();
	}

private:
	inline void _check_defsptr(const dynamic_field_info& i, bool write) const {
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

	inline void* _access_dynamic_field_for_write(size_t index) {
		if(!m_dynamic_fields) {
			throw sinsp_exception("dynamic struct has no field definitions");
		}
		if(index >= m_dynamic_fields->m_definitions_ordered.size()) {
			throw sinsp_exception("dynamic struct access overflow: " + std::to_string(index));
		}
		while(m_fields.size() <= index) {
			auto def = m_dynamic_fields->m_definitions_ordered[m_fields.size()];
			void* fieldbuf = malloc(def->info().size());
			def->info().construct(fieldbuf);
			m_fields.push_back(fieldbuf);
		}
		return m_fields[index];
	}

	inline void* _access_dynamic_field_for_read(size_t index) const {
		if(!m_dynamic_fields) {
			throw sinsp_exception("dynamic struct has no field definitions");
		}
		if(index >= m_dynamic_fields->m_definitions_ordered.size()) {
			throw sinsp_exception("dynamic struct access overflow: " + std::to_string(index));
		}
		if(m_fields.size() <= index) {
			return nullptr;
		}
		return m_fields[index];
	}

	inline void deep_fields_copy(const extensible_struct& other_const) {
		// note: const cast should be safe here as we're not going to resize
		// nor edit the dynamic fields allocated in "other"
		auto& other = const_cast<extensible_struct&>(other_const);

		// copy the definitions
		set_dynamic_fields(other.dynamic_fields());

		// deep copy of all the fields
		destroy_dynamic_fields();
		for(size_t i = 0; i < other.m_fields.size(); i++) {
			const auto info = m_dynamic_fields->m_definitions_ordered[i];
			// note: we use uintptr_t as it fits all the data types supported for
			// reading and writing dynamic fields (e.g. uint32_t, uint64_t, const char*,
			// base_table*, ...)
			uintptr_t val = 0;
			other.get_dynamic_field(*info, reinterpret_cast<void*>(&val));
			set_dynamic_field(*info, &val);
		}
	}

	std::vector<void*> m_fields;
	std::shared_ptr<dynamic_field_infos> m_dynamic_fields;
	// end of dynamic_struct interface

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

template<>
inline void libsinsp::state::extensible_struct::get_dynamic_field<std::string, const char*>(
        const dynamic_field_accessor<std::string>& a,
        const char*& out) {
	_check_defsptr(a.info(), false);
	get_dynamic_field(a.info(), reinterpret_cast<void*>(&out));
}

template<>
inline void libsinsp::state::extensible_struct::get_dynamic_field<std::string, std::string>(
        const dynamic_field_accessor<std::string>& a,
        std::string& out) {
	const char* s = NULL;
	get_dynamic_field(a, s);
	if(!s) {
		out.clear();
	} else {
		out = s;
	}
}

template<>
inline void libsinsp::state::extensible_struct::set_dynamic_field<std::string, const char*>(
        const dynamic_field_accessor<std::string>& a,
        const char* const& in) {
	_check_defsptr(a.info(), true);
	set_dynamic_field(a.info(), reinterpret_cast<const void*>(&in));
}

template<>
inline void libsinsp::state::extensible_struct::set_dynamic_field<std::string, std::string>(
        const dynamic_field_accessor<std::string>& a,
        const std::string& in) {
	set_dynamic_field(a, in.c_str());
}

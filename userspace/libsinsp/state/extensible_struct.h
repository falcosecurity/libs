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

	struct reader {
		const extensible_struct* self;
		const static_field_accessor* acc;

		template<typename T>
		borrowed_state_data operator()() const {
			const T* ptr = reinterpret_cast<const T*>(reinterpret_cast<const char*>(self) +
			                                          acc->info().offset());

			return borrowed_state_data::from<type_id_of<T>(), T>(*ptr);
		}
	};

	[[nodiscard]] borrowed_state_data raw_read_field(const accessor& a) const override {
		if(auto static_acc = dynamic_cast<const static_field_accessor*>(&a)) {
			if(!static_acc->info().valid()) {
				throw sinsp_exception("can't get invalid field in static struct");
			}
			return dispatch_lambda(a.type_id(), reader{this, static_acc});
		}

		if(auto dynamic_acc = dynamic_cast<const dynamic_field_accessor*>(&a)) {
			_check_defsptr(dynamic_acc->info(), false);
			if(auto ptr = _access_dynamic_field_for_read(dynamic_acc->info().index())) {
				return borrowed_state_data(ptr->m_data);
			}
			return {};
		}

#ifdef _MSC_VER
		_assume(0);
#else
		__builtin_unreachable();
#endif
	}

protected:
	struct writer {
		extensible_struct* self;
		const accessor* acc;
		const void* in;

		template<typename T>
		void operator()() const {
			if(auto static_acc = dynamic_cast<const static_field_accessor*>(acc)) {
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

			if(auto dynamic_acc = dynamic_cast<const dynamic_field_accessor*>(acc)) {
				self->_check_defsptr(dynamic_acc->info(), true);
				auto ptr = self->_access_dynamic_field_for_write(dynamic_acc->info().index());
				auto val = static_cast<const T*>(in);
				ptr->update(borrowed_state_data::from<type_id_of<T>(), T>(*val));
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
		return dispatch_lambda(a.type_id(), writer{this, &a, in});
	}
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
 * @param offset Field's memory offset in instances of the class/struct.
 * @param name Display name of the field.
 * @param readonly Read-only field annotation.
 */
template<typename T>
constexpr static const static_field_info& define_static_field(static_field_infos& fields,
                                                              const size_t offset,
                                                              const std::string& name,
                                                              const bool readonly = false) {
	const auto& it = fields.find(name);
	if(it != fields.end()) {
		throw sinsp_exception("multiple definitions of static field in struct: " + name);
	}

	// todo(jasondellaluce): add extra safety boundary checks here
	fields.insert({name, static_field_info(name, offset, type_id_of<T>(), readonly)});
	return fields.at(name);
}

}  // namespace libsinsp::state

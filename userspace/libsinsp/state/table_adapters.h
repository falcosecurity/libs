// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.
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

#include <libsinsp/state/table.h>

namespace libsinsp {
namespace state {

/**
 * @brief A subclass of dynamic_struct::field_infos that have a fixed,
 * and immutable, list of dynamic field definitions all declared at
 * construction-time
 */
class fixed_dynamic_fields_infos : public dynamic_struct::field_infos {
public:
	virtual ~fixed_dynamic_fields_infos() = default;

	inline fixed_dynamic_fields_infos(std::initializer_list<dynamic_struct::field_info> infos):
	        field_infos(infos.begin()->defs_id()) {
		auto defs_id = infos.begin()->defs_id();
		for(const auto& f : infos) {
			if(f.defs_id() != defs_id) {
				throw sinsp_exception(
				        "inconsistent definition ID passed to fixed_dynamic_fields_infos");
			}
			field_infos::add_field_info(f);
		}
	}

protected:
	const dynamic_struct::field_info& add_field_info(
	        const dynamic_struct::field_info& field) override final {
		throw sinsp_exception("can't add field to fixed_dynamic_fields_infos: " + field.name());
	}
};

/**
 * @brief An adapter for the libsinsp::state::table_entry interface
 * that wraps a non-owning pointer of arbitrary type T. The underlying pointer
 * can be set and unset arbitrarily, making this wrapper suitable for optimized
 * allocations. Instances of table_entry from this adapter have no static fields,
 * and make the wrapped value available as a single dynamic field. The dynamic
 * fields definitions of this wrapper are fixed and immutable.
 */
template<typename T>
class value_table_entry_adapter : public libsinsp::state::table_entry {
public:
	// note: this dynamic definitions are fixed in size and structure,
	// so there's no need of worrying about specific identifier checks
	// as they should be safely interchangeable
	static const constexpr uintptr_t s_dynamic_fields_id = 1234;

	struct dynamic_fields_t : public fixed_dynamic_fields_infos {
		using _dfi = dynamic_struct::field_info;

		inline dynamic_fields_t():
		        fixed_dynamic_fields_infos({_dfi::build<T>("value", 0, s_dynamic_fields_id)}) {}

		virtual ~dynamic_fields_t() = default;
	};

	inline explicit value_table_entry_adapter(): table_entry(nullptr), m_value(nullptr) {}

	virtual ~value_table_entry_adapter() = default;

	inline T* value() { return m_value; }

	inline const T* value() const { return m_value; }

	inline void set_value(T* v) { m_value = v; }

protected:
	virtual void get_dynamic_field(const dynamic_struct::field_info& i, void* out) override final {
		if(i.index() != 0 || i.defs_id() != s_dynamic_fields_id) {
			throw sinsp_exception(
			        "invalid field info passed to value_table_entry_adapter::get_dynamic_field");
		}

		if(i.info().index() == typeinfo::index_t::TI_STRING) {
			*((const char**)out) = ((const std::string*)m_value)->c_str();
		} else if(i.info().index() == typeinfo::index_t::TI_STRINGPAIR) {
			auto ostrs = *((const char*(*)[2])out);
			auto pval = (const libsinsp::state::pair_t*)m_value;
			ostrs[0] = pval->first.c_str();
			ostrs[1] = pval->second.c_str();
		} else {
			memcpy(out, (const void*)m_value, i.info().size());
		}
	}

	virtual void set_dynamic_field(const dynamic_struct::field_info& i,
	                               const void* in) override final {
		if(i.index() != 0 || i.defs_id() != s_dynamic_fields_id) {
			throw sinsp_exception(
			        "invalid field info passed to value_table_entry_adapter::set_dynamic_field");
		}

		if(i.info().index() == typeinfo::index_t::TI_STRING) {
			*((std::string*)m_value) = *((const char**)in);
		} else if(i.info().index() == typeinfo::index_t::TI_STRINGPAIR) {
			auto istrs = *((const char*(*)[2])in);
			auto pval = (libsinsp::state::pair_t*)m_value;
			pval->first = istrs[0];
			pval->second = istrs[1];
		} else {
			memcpy((void*)m_value, in, i.info().size());
		}
	}

	virtual void destroy_dynamic_fields() override final {
		// nothing to do
	}

private:
	T* m_value;
};

/**
 * @brief A template that helps converting STL container types (e.g.
 * std::vector, std::list, etc) into tables compatible with the libsinsp
 * state API.
 *
 * In this context, array-like types are mapped as tables with an uint64_t key
 * representing the index of the element in the array -- as such, users should
 * be extra careful when performing addition or deletion operations, as that
 * can lead to expensive sparse array operations or results.
 */
template<typename T,
         typename TWrap = value_table_entry_adapter<typename T::value_type>,
         typename DynFields = typename TWrap::dynamic_fields_t>
class stl_container_table_adapter : public libsinsp::state::table<uint64_t> {
public:
	stl_container_table_adapter(const std::string& name, T& container):
	        table(name, _static_fields()),
	        m_container(container) {
		set_dynamic_fields(std::make_shared<DynFields>());
	}

	virtual ~stl_container_table_adapter() = default;

	size_t entries_count() const override { return m_container.size(); }

	void clear_entries() override { m_container.clear(); }

	std::unique_ptr<libsinsp::state::table_entry> new_entry() const override {
		auto ret = std::make_unique<TWrap>();
		ret->set_dynamic_fields(this->dynamic_fields());
		return ret;
	}

	bool foreach_entry(std::function<bool(libsinsp::state::table_entry& e)> pred) override {
		TWrap w;
		w.set_dynamic_fields(this->dynamic_fields());
		for(auto& v : m_container) {
			w.set_value(&v);
			if(!pred(w)) {
				return false;
			}
		}
		return true;
	}

	std::shared_ptr<libsinsp::state::table_entry> get_entry(const uint64_t& key) override {
		if(key >= m_container.size()) {
			return nullptr;
		}
		return wrap_value(&m_container[key]);
	}

	std::shared_ptr<libsinsp::state::table_entry> add_entry(
	        const uint64_t& key,
	        std::unique_ptr<libsinsp::state::table_entry> entry) override {
		if(!entry) {
			throw sinsp_exception("null entry added to table: " + this->name());
		}
		if(entry->dynamic_fields() != this->dynamic_fields()) {
			throw sinsp_exception("entry with mismatching dynamic fields added to table: " +
			                      this->name());
		}

		auto value = dynamic_cast<TWrap*>(entry.get());
		if(!value) {
			throw sinsp_exception("entry with mismatching type added to table: " + this->name());
		}
		if(value->value() != nullptr) {
			throw sinsp_exception("entry with unexpected owned value added to table: " +
			                      this->name());
		}

		m_container.resize(key + 1);
		return wrap_value(&m_container[key]);
	}

	bool erase_entry(const uint64_t& key) override {
		if(key >= m_container.size()) {
			return false;
		}
		m_container.erase(m_container.begin() + key);
		return true;
	}

private:
	static inline const static_struct::field_infos* _static_fields() {
		static const auto s_fields = TWrap{}.static_fields();
		return &s_fields;
	}

	static inline void wrap_deleter(TWrap* v) { v->set_value(nullptr); }

	// helps us dynamically allocate a batch of wrappers, creating new ones
	// only if we need them. Wrappers are reused for multiple entries, and
	// we leverage shared_ptrs to automatically release them once not anymore used
	inline std::shared_ptr<libsinsp::state::table_entry> wrap_value(typename T::value_type* v) {
		for(auto& w : m_wrappers) {
			if(w.value() == nullptr) {
				w.set_value(v);
				return std::shared_ptr<libsinsp::state::table_entry>(&w, wrap_deleter);
			}
		}

		// no wrapper is free among the allocated ones so add an extra one
		auto& w = m_wrappers.emplace_back();
		w.set_value(v);
		w.set_dynamic_fields(this->dynamic_fields());
		return std::shared_ptr<libsinsp::state::table_entry>(&w, wrap_deleter);
	}

	T& m_container;
	std::list<TWrap> m_wrappers;  // using lists for ptr stability
};

};  // namespace state
};  // namespace libsinsp

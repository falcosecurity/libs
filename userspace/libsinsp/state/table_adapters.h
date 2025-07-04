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
 * @brief A subclass of dynamic_field_infos that have a fixed,
 * and immutable, list of dynamic field definitions all declared at
 * construction-time
 */
class fixed_dynamic_fields_infos : public dynamic_field_infos {
public:
	virtual ~fixed_dynamic_fields_infos() = default;

	inline fixed_dynamic_fields_infos(std::initializer_list<dynamic_field_info> infos):
	        dynamic_field_infos(infos.begin()->defs_id()) {
		auto defs_id = infos.begin()->defs_id();
		for(const auto& f : infos) {
			if(f.defs_id() != defs_id) {
				throw sinsp_exception(
				        "inconsistent definition ID passed to fixed_dynamic_fields_infos");
			}
			dynamic_field_infos::add_field_info(f);
		}
	}

protected:
	const dynamic_field_info& add_field_info(const dynamic_field_info& field) override final {
		throw sinsp_exception("can't add field to fixed_dynamic_fields_infos: " + field.name());
	}
};

/**
 * @brief An adapter for the libsinsp::state::table_entry interface
 * that wraps a non-owning pointer of arbitrary pair of type T. The underlying pointer
 * can be set and unset arbitrarily, making this wrapper suitable for optimized
 * allocations. Instances of table_entry from this adapter have no static fields,
 * and make the wrapped value available as a single dynamic field. The dynamic
 * fields definitions of this wrapper are fixed and immutable.
 */
template<typename Tfirst, typename Tsecond>
class pair_table_entry_adapter : public libsinsp::state::table_entry {
public:
	// note: this dynamic definitions are fixed in size and structure,
	// so there's no need of worrying about specific identifier checks
	// as they should be safely interchangeable
	static const constexpr uintptr_t s_dynamic_fields_id = 4321;

	struct dynamic_fields_t : public fixed_dynamic_fields_infos {
		using _dfi = dynamic_field_info;

		inline dynamic_fields_t():
		        fixed_dynamic_fields_infos(
		                {_dfi::build<Tfirst>("first", 0, s_dynamic_fields_id),
		                 _dfi::build<Tsecond>("second", 1, s_dynamic_fields_id)}) {}

		virtual ~dynamic_fields_t() = default;
	};

	inline explicit pair_table_entry_adapter(): table_entry(nullptr), m_value(nullptr) {}

	inline std::pair<Tfirst, Tsecond>* value() { return m_value; }
	inline const std::pair<Tfirst, Tsecond>* value() const { return m_value; }
	inline void set_value(std::pair<Tfirst, Tsecond>* v) { m_value = v; }

protected:
	struct reader {
		const pair_table_entry_adapter* self;
		const accessor* acc;

		template<typename U>
		const void* operator()() const {
			auto field_acc = dynamic_cast<const dynamic_field_accessor<U>*>(acc);
			const auto& i = field_acc->info();

			if(i.index() > 1 || i.defs_id() != s_dynamic_fields_id) {
				throw sinsp_exception(
				        "invalid field info passed to pair_table_entry_adapter::read_field");
			}
			if(i.index() == 0) {
				return &self->m_value->first;
			}
			return &self->m_value->second;
		}
	};

	const void* raw_read_field(const accessor& a) const override {
		return dispatch_lambda(a.type_info().type_id(), reader{this, &a});
	}

	struct writer {
		pair_table_entry_adapter* self;
		const accessor* acc;
		const void* in;

		template<typename U>
		void operator()() const {
			auto field_acc = dynamic_cast<const dynamic_field_accessor<U>*>(acc);
			const auto& i = field_acc->info();

			if(i.index() > 1 || i.defs_id() != s_dynamic_fields_id) {
				throw sinsp_exception(
				        "invalid field info passed to pair_table_entry_adapter::write_field");
			}

			if(i.index() == 0) {
				self->m_value->first = *static_cast<const Tfirst*>(in);
			} else {
				self->m_value->second = *static_cast<const Tsecond*>(in);
			}
		}
	};
	void raw_write_field(const accessor& a, const void* in) override {
		return dispatch_lambda(a.type_info().type_id(), writer{this, &a, in});
	}

	virtual void get_dynamic_field(const dynamic_field_info& i, void* out) override final {
		if(i.index() > 1 || i.defs_id() != s_dynamic_fields_id) {
			throw sinsp_exception(
			        "invalid field info passed to pair_table_entry_adapter::get_dynamic_field");
		}
		if(i.index() == 0) {
			return get_dynamic_field(i, &m_value->first, out);
		}
		return get_dynamic_field(i, &m_value->second, out);
	}

	virtual void set_dynamic_field(const dynamic_field_info& i, const void* in) override final {
		if(i.index() > 1 || i.defs_id() != s_dynamic_fields_id) {
			throw sinsp_exception(
			        "invalid field info passed to pair_table_entry_adapter::set_dynamic_field");
		}

		if(i.index() == 0) {
			return set_dynamic_field(i, &m_value->first, in);
		}
		return set_dynamic_field(i, &m_value->second, in);
	}

	virtual void destroy_dynamic_fields() override final {
		// nothing to do
	}

private:
	std::pair<Tfirst, Tsecond>* m_value;

	template<typename T>
	inline void get_dynamic_field(const dynamic_field_info& i, const T* value, void* out) {
		if(i.info().type_id() == SS_PLUGIN_ST_STRING) {
			*((const char**)out) = ((const std::string*)value)->c_str();
		} else {
			memcpy(out, (const void*)value, i.info().size());
		}
	}

	template<typename T>
	inline void set_dynamic_field(const dynamic_field_info& i, T* value, const void* in) {
		if(i.info().type_id() == SS_PLUGIN_ST_STRING) {
			*((std::string*)value) = *((const char**)in);
		} else {
			memcpy((void*)value, in, i.info().size());
		}
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
		using _dfi = dynamic_field_info;

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
	struct reader {
		const value_table_entry_adapter* self;
		const accessor* acc;

		template<typename U>
		const void* operator()() const {
			auto field_acc = dynamic_cast<const dynamic_field_accessor<U>*>(acc);
			const auto& i = field_acc->info();

			if(i.index() != 0 || i.defs_id() != s_dynamic_fields_id) {
				throw sinsp_exception(
				        "invalid field info passed to value_table_entry_adapter::read_field");
			}

			return self->m_value;
		}
	};

	const void* raw_read_field(const accessor& a) const override {
		return dispatch_lambda(a.type_info().type_id(), reader{this, &a});
	}

	struct writer {
		value_table_entry_adapter* self;
		const accessor* acc;
		const void* in;

		template<typename U>
		void operator()() const {
			auto field_acc = dynamic_cast<const dynamic_field_accessor<U>*>(acc);
			const auto& i = field_acc->info();

			if(i.index() != 0 || i.defs_id() != s_dynamic_fields_id) {
				throw sinsp_exception(
				        "invalid field info passed to value_table_entry_adapter::write_field");
			}

			*self->m_value = *static_cast<const T*>(in);
		}
	};

	void raw_write_field(const accessor& a, const void* in) override {
		return dispatch_lambda(a.type_info().type_id(), writer{this, &a, in});
	}

	virtual void get_dynamic_field(const dynamic_field_info& i, void* out) override final {
		if(i.index() != 0 || i.defs_id() != s_dynamic_fields_id) {
			throw sinsp_exception(
			        "invalid field info passed to value_table_entry_adapter::get_dynamic_field");
		}

		if(i.info().type_id() == SS_PLUGIN_ST_STRING) {
			*((const char**)out) = ((const std::string*)m_value)->c_str();
		} else {
			memcpy(out, (const void*)m_value, i.info().size());
		}
	}

	virtual void set_dynamic_field(const dynamic_field_info& i, const void* in) override final {
		if(i.index() != 0 || i.defs_id() != s_dynamic_fields_id) {
			throw sinsp_exception(
			        "invalid field info passed to value_table_entry_adapter::set_dynamic_field");
		}

		if(i.info().type_id() == SS_PLUGIN_ST_STRING) {
			*((std::string*)m_value) = *((const char**)in);
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
class stl_container_table_adapter : public libsinsp::state::built_in_table<uint64_t> {
public:
	stl_container_table_adapter(const std::string& name, T& container):
	        built_in_table(name, _static_fields()),
	        m_container(container) {
		set_dynamic_fields(std::make_shared<DynFields>());
	}

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
			throw sinsp_exception(
			        std::string("null entry added to table: " + std::string(this->name())));
		}
		if(entry->dynamic_fields() != this->dynamic_fields()) {
			throw sinsp_exception("entry with mismatching dynamic fields added to table: " +
			                      std::string(this->name()));
		}

		auto value = dynamic_cast<TWrap*>(entry.get());
		if(!value) {
			throw sinsp_exception("entry with mismatching type added to table: " +
			                      std::string(this->name()));
		}
		if(value->value() != nullptr) {
			throw sinsp_exception("entry with unexpected owned value added to table: " +
			                      std::string(this->name()));
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
	using field_infos = std::unordered_map<std::string, static_field_info>;
	static inline const field_infos* _static_fields() {
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

// Simple adapter for ss_plugin_table_input that implements the base_table interface
class table_input_adapter : public libsinsp::state::base_table {
private:
	ss_plugin_table_input* m_input;
	std::string m_name;

public:
	explicit table_input_adapter(ss_plugin_table_input* input):
	        libsinsp::state::base_table(libsinsp::state::typeinfo::from(input->key_type)),
	        m_input(input),
	        m_name(input->name ? input->name : "unknown") {}

	// ss_plugin_table_t is an opaque pointer to ss_plugin_table_input
	explicit table_input_adapter(ss_plugin_table_t* table):
	        table_input_adapter(static_cast<ss_plugin_table_input*>(table)) {}

	const char* name() const override { return m_name.c_str(); }

	const ss_plugin_table_fieldinfo* list_fields(libsinsp::state::sinsp_table_owner* owner,
	                                             uint32_t* nfields) override {
		return m_input->fields.list_table_fields(m_input->table, nfields);
	}

	ss_plugin_table_field_t* get_field(libsinsp::state::sinsp_table_owner* owner,
	                                   const char* name,
	                                   ss_plugin_state_type data_type) override {
		return m_input->fields.get_table_field(m_input->table, name, data_type);
	}

	ss_plugin_table_field_t* add_field(libsinsp::state::sinsp_table_owner* owner,
	                                   const char* name,
	                                   ss_plugin_state_type data_type) override {
		return m_input->fields.add_table_field(m_input->table, name, data_type);
	}

	uint64_t get_size(libsinsp::state::sinsp_table_owner* owner) override {
		return m_input->reader.get_table_size(m_input->table);
	}

	ss_plugin_table_entry_t* get_entry(libsinsp::state::sinsp_table_owner* owner,
	                                   const ss_plugin_state_data* key) override {
		return m_input->reader.get_table_entry(m_input->table, key);
	}

	void release_table_entry(libsinsp::state::sinsp_table_owner* owner,
	                         ss_plugin_table_entry_t* _e) override {
		m_input->reader_ext->release_table_entry(m_input->table, _e);
	}

	ss_plugin_bool iterate_entries(libsinsp::state::sinsp_table_owner* owner,
	                               ss_plugin_table_iterator_func_t it,
	                               ss_plugin_table_iterator_state_t* s) override {
		return m_input->reader_ext->iterate_entries(m_input->table, it, s);
	}

	ss_plugin_rc read_entry_field(libsinsp::state::sinsp_table_owner* owner,
	                              ss_plugin_table_entry_t* _e,
	                              const ss_plugin_table_field_t* f,
	                              ss_plugin_state_data* out) override {
		return m_input->reader.read_entry_field(m_input->table, _e, f, out);
	}

	ss_plugin_rc clear_entries(libsinsp::state::sinsp_table_owner* owner) override {
		return m_input->writer.clear_table(m_input->table);
	}

	ss_plugin_rc erase_entry(libsinsp::state::sinsp_table_owner* owner,
	                         const ss_plugin_state_data* key) override {
		return m_input->writer.erase_table_entry(m_input->table, key);
	}

	ss_plugin_table_entry_t* create_table_entry(
	        libsinsp::state::sinsp_table_owner* owner) override {
		return m_input->writer.create_table_entry(m_input->table);
	}

	void destroy_table_entry(libsinsp::state::sinsp_table_owner* owner,
	                         ss_plugin_table_entry_t* _e) override {
		m_input->writer.destroy_table_entry(m_input->table, _e);
	}

	ss_plugin_table_entry_t* add_entry(libsinsp::state::sinsp_table_owner* owner,
	                                   const ss_plugin_state_data* key,
	                                   ss_plugin_table_entry_t* _e) override {
		return m_input->writer.add_table_entry(m_input->table, key, _e);
	}

	ss_plugin_rc write_entry_field(libsinsp::state::sinsp_table_owner* owner,
	                               ss_plugin_table_entry_t* _e,
	                               const ss_plugin_table_field_t* f,
	                               const ss_plugin_state_data* in) override {
		return m_input->writer.write_entry_field(m_input->table, _e, f, in);
	}
};

};  // namespace state
};  // namespace libsinsp

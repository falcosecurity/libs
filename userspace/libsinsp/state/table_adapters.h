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
	inline explicit pair_table_entry_adapter(): m_value(nullptr) {}

	inline std::pair<Tfirst, Tsecond>* value() { return m_value; }
	inline const std::pair<Tfirst, Tsecond>* value() const { return m_value; }
	inline void set_value(std::pair<Tfirst, Tsecond>* v) { m_value = v; }

	static void list_fields(std::vector<ss_plugin_table_fieldinfo>& out) {
		ss_plugin_table_fieldinfo first = {"first", type_id_of<Tfirst>(), false};
		out.emplace_back(first);
		ss_plugin_table_fieldinfo second = {"second", type_id_of<Tsecond>(), false};
		out.emplace_back(second);
	}

	static accessor::ptr get_field(const char* name, ss_plugin_state_type type_id) {
		if(strcmp(name, "first") == 0) {
			auto tinfo = type_id_of<Tfirst>();
			if(type_id != tinfo) {
				throw sinsp_exception("incompatible type for pair_table_entry_adapter field: " +
				                      std::string(name));
			}
			return accessor::ptr(std::make_unique<accessor>(tinfo, read_key, nullptr, 0));
		} else if(strcmp(name, "second") == 0) {
			auto tinfo = type_id_of<Tsecond>();
			if(type_id != tinfo) {
				throw sinsp_exception("incompatible type for pair_table_entry_adapter field: " +
				                      std::string(name));
			}
			return accessor::ptr(std::make_unique<accessor>(tinfo, read_value, nullptr, 1));
		}
		throw sinsp_exception(std::string("field ") + name + " not found");
	}

	void raw_write_field(const accessor& a, const borrowed_state_data& in) override {
		if(a.index() == 0) {
			if(a.type_id() != type_id_of<Tfirst>()) {
				throw sinsp_exception("incompatible type for pair_table_entry_adapter field: " +
				                      std::string(type_name(a.type_id())));
			}
			in.copy_to<type_id_of<Tfirst>(), Tfirst>(m_value->first);
			return;
		} else {
			if(a.type_id() != type_id_of<Tsecond>()) {
				throw sinsp_exception("incompatible type for pair_table_entry_adapter field: " +
				                      std::string(type_name(a.type_id())));
			}
			in.copy_to<type_id_of<Tsecond>(), Tsecond>(m_value->second);
			return;
		}
	}

private:
	[[nodiscard]] static borrowed_state_data read_key(const void* obj, size_t) {
		const auto* v = static_cast<const pair_table_entry_adapter*>(obj);
		return borrowed_state_data::from<type_id_of<Tfirst>(), Tfirst>(v->m_value->first);
	}

	[[nodiscard]] static borrowed_state_data read_value(const void* obj, size_t) {
		const auto* v = static_cast<const pair_table_entry_adapter*>(obj);
		return borrowed_state_data::from<type_id_of<Tsecond>(), Tfirst>(v->m_value->second);
	}

	std::pair<Tfirst, Tsecond>* m_value;
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
	inline explicit value_table_entry_adapter(): m_value(nullptr) {}

	virtual ~value_table_entry_adapter() = default;

	inline T* value() { return m_value; }

	inline const T* value() const { return m_value; }

	inline void set_value(T* v) { m_value = v; }

	static void list_fields(std::vector<ss_plugin_table_fieldinfo>& out) {
		ss_plugin_table_fieldinfo value = {"value", type_id_of<T>(), false};
		out.emplace_back(value);
	}

	static accessor::ptr get_field(const char* name, ss_plugin_state_type type_id) {
		if(strcmp(name, "value") == 0) {
			auto tinfo = type_id_of<T>();
			if(type_id != tinfo) {
				throw sinsp_exception("incompatible type for value_table_entry_adapter field: " +
				                      std::string(name));
			}
			return accessor::ptr(std::make_unique<accessor>(tinfo, read_value, nullptr, 0));
		}
		throw sinsp_exception(std::string("field ") + name + " not found");
	}

protected:
	void raw_write_field(const accessor& a, const borrowed_state_data& in) override {
		if(a.type_id() != type_id_of<T>()) {
			throw sinsp_exception("incompatible type for value_table_entry_adapter field: " +
			                      std::string(type_name(a.type_id())));
		}
		if(a.index() != 0) {
			throw sinsp_exception(
			        "invalid field info passed to value_table_entry_adapter::write_field");
		}
		in.copy_to<type_id_of<T>(), T>(*m_value);
	}

private:
	[[nodiscard]] static borrowed_state_data read_value(const void* obj, size_t) {
		const auto* v = static_cast<const value_table_entry_adapter*>(obj);
		return borrowed_state_data::from<type_id_of<T>(), T>(*v->m_value);
	}

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
template<typename T, typename TWrap = value_table_entry_adapter<typename T::value_type>>
class stl_container_table_adapter : public libsinsp::state::built_in_table<uint64_t> {
public:
	stl_container_table_adapter(const std::string& name, T& container):
	        built_in_table(name),
	        m_container(container) {}

	void list_fields(std::vector<ss_plugin_table_fieldinfo>& out) override {
		TWrap::list_fields(out);
	}

	accessor::ptr get_field(const char* name, ss_plugin_state_type type_id) override {
		return TWrap::get_field(name, type_id);
	}

	accessor::ptr add_field(const char* name, ss_plugin_state_type type_id) override {
		throw sinsp_exception("can't add dynamic fields to stl_container_table_adapter");
	}

	size_t entries_count() const override { return m_container.size(); }

	void clear_entries() override { m_container.clear(); }

	std::unique_ptr<libsinsp::state::table_entry> new_entry() const override {
		auto ret = std::make_unique<TWrap>();
		return ret;
	}

	bool foreach_entry(std::function<bool(libsinsp::state::table_entry& e)> pred) override {
		TWrap w;
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
	        libsinsp::state::base_table(input->key_type),
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

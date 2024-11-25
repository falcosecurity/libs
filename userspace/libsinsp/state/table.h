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

#include <libscap/scap_assert.h>
#include <libsinsp/sinsp_exception.h>
#include <libsinsp/state/static_struct.h>
#include <libsinsp/state/dynamic_struct.h>
#include <plugin/plugin_api.h>

#include <functional>
#include <type_traits>
#include <memory>
#include <list>

namespace libsinsp {
namespace state {
class sinsp_table_owner;
struct sinsp_table_wrapper;

// wraps instances of libsinsp::state::XXX_struct::field_accessor and
// help making them comply to the plugin API state tables definitions
struct sinsp_field_accessor_wrapper {
	// depending on the value of `dynamic`, one of:
	// - libsinsp::state::static_struct::field_accessor
	// - libsinsp::state::dynamic_struct::field_accessor
	void* accessor = nullptr;
	bool dynamic = false;
	ss_plugin_state_type data_type = ss_plugin_state_type::SS_PLUGIN_ST_INT8;
	ss_plugin_state_type subtable_key_type = ss_plugin_state_type::SS_PLUGIN_ST_INT8;

	inline sinsp_field_accessor_wrapper() = default;
	~sinsp_field_accessor_wrapper();
	inline sinsp_field_accessor_wrapper(const sinsp_field_accessor_wrapper& s) = delete;
	inline sinsp_field_accessor_wrapper& operator=(const sinsp_field_accessor_wrapper& s) = delete;
	sinsp_field_accessor_wrapper(sinsp_field_accessor_wrapper&& s);
	sinsp_field_accessor_wrapper& operator=(sinsp_field_accessor_wrapper&& s);
};

/**
 * @brief Base class for entries of a state table.
 */
struct table_entry : public static_struct, dynamic_struct {
	table_entry(const std::shared_ptr<dynamic_struct::field_infos>& dyn_fields):
	        static_struct(),
	        dynamic_struct(dyn_fields) {}
	virtual ~table_entry() = default;
	table_entry(table_entry&&) = default;
	table_entry& operator=(table_entry&&) = default;
	table_entry(const table_entry& s) = default;
	table_entry& operator=(const table_entry& s) = default;
};

template<typename KeyType>
class table;

// wraps instances of libsinsp::state::table and help making them comply
// to the plugin API state tables definitions
struct table_accessor {
	sinsp_table_owner* m_owner_plugin = nullptr;
	libsinsp::state::base_table* m_table = nullptr;

	// plugin-defined vtables
	ss_plugin_table_input input;
	ss_plugin_table_fields_vtable_ext fields_vtable;
	ss_plugin_table_reader_vtable_ext reader_vtable;
	ss_plugin_table_writer_vtable_ext writer_vtable;

	table_accessor();
	virtual ~table_accessor() = default;
	inline table_accessor(const table_accessor& s) = delete;
	inline table_accessor& operator=(const table_accessor& s) = delete;

	void unset();
	bool is_set() const;
	template<typename T>
	void set(sinsp_table_owner* p, libsinsp::state::table<T>* t);

	// static functions, will be used to populate vtable functions where
	// ss_plugin_table_t* will point to a `table_accessor` instance
	static inline const ss_plugin_table_fieldinfo* list_fields(ss_plugin_table_t* _t,
	                                                           uint32_t* nfields);
	static inline ss_plugin_table_field_t* get_field(ss_plugin_table_t* _t,
	                                                 const char* name,
	                                                 ss_plugin_state_type data_type);
	static inline ss_plugin_table_field_t* add_field(ss_plugin_table_t* _t,
	                                                 const char* name,
	                                                 ss_plugin_state_type data_type);
	static inline const char* get_name(ss_plugin_table_t* _t);
	static inline uint64_t get_size(ss_plugin_table_t* _t);
	static inline ss_plugin_table_entry_t* get_entry(ss_plugin_table_t* _t,
	                                                 const ss_plugin_state_data* key);
	static inline ss_plugin_rc read_entry_field(ss_plugin_table_t* _t,
	                                            ss_plugin_table_entry_t* _e,
	                                            const ss_plugin_table_field_t* f,
	                                            ss_plugin_state_data* out);
	;
	static inline void release_table_entry(ss_plugin_table_t* _t, ss_plugin_table_entry_t* _e);
	static inline ss_plugin_bool iterate_entries(ss_plugin_table_t* _t,
	                                             ss_plugin_table_iterator_func_t it,
	                                             ss_plugin_table_iterator_state_t* s);
	static inline ss_plugin_rc clear(ss_plugin_table_t* _t);
	static inline ss_plugin_rc erase_entry(ss_plugin_table_t* _t, const ss_plugin_state_data* key);
	static inline ss_plugin_table_entry_t* create_table_entry(ss_plugin_table_t* _t);
	static inline void destroy_table_entry(ss_plugin_table_t* _t, ss_plugin_table_entry_t* _e);
	static inline ss_plugin_table_entry_t* add_entry(ss_plugin_table_t* _t,
	                                                 const ss_plugin_state_data* key,
	                                                 ss_plugin_table_entry_t* _e);
	static inline ss_plugin_rc write_entry_field(ss_plugin_table_t* _t,
	                                             ss_plugin_table_entry_t* e,
	                                             const ss_plugin_table_field_t* f,
	                                             const ss_plugin_state_data* in);
	;
};

/**
 * @brief Base non-templated interface for state tables, defining
 * type-independent properties common to all tables.
 */
class base_table {
public:
	inline base_table(const std::string& name,
	                  const typeinfo& key_info,
	                  const static_struct::field_infos* static_fields):
	        m_this_ptr(this),
	        m_name(name),
	        m_key_info(key_info),
	        m_static_fields(static_fields),
	        m_dynamic_fields(std::make_shared<dynamic_struct::field_infos>()) {}

	virtual ~base_table() = default;
	inline base_table(base_table&&) = default;
	inline base_table& operator=(base_table&&) = default;
	inline base_table(const base_table& s) = delete;
	inline base_table& operator=(const base_table& s) = delete;

	/**
	 * @brief Returns a pointer to the area of memory in which this table
	 * object is allocated. Here for convenience as required in other code parts.
	 */
	inline const base_table* const& table_ptr() const { return m_this_ptr; }

	/**
	 * @brief Returns the name of the table.
	 */
	inline const std::string& name() const { return m_name; }

	/**
	 * @brief Returns the non-null type info about the table's key.
	 */
	inline const typeinfo& key_info() const { return m_key_info; }

	/**
	 * @brief Returns the fields metadata list for the static fields defined
	 * for the value data type of this table. This fields will be accessible
	 * for all the entries of this table.
	 */
	virtual const static_struct::field_infos* static_fields() const { return m_static_fields; }

	/**
	 * @brief Returns the fields metadata list for the dynamic fields defined
	 * for the value data type of this table. This fields will be accessible
	 * for all the entries of this table. The returned metadata list can
	 * be expended at runtime by adding new dynamic fields, which will then
	 * be allocated and accessible for all the present and future entries
	 * present in the table.
	 */
	virtual const std::shared_ptr<dynamic_struct::field_infos>& dynamic_fields() const {
		return m_dynamic_fields;
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

	/**
	 * @brief Returns the number of entries present in the table.
	 */
	virtual size_t entries_count() const = 0;

	/**
	 * @brief Erase all the entries present in the table.
	 * After invoking this function, entries_count() will return true.
	 */
	virtual void clear_entries() = 0;

	/**
	 * @brief Allocates and returns a new entry for the table. This is just
	 * a factory method, the entry will not automatically added to the table.
	 * Once a new entry is allocated with this method, users must invoke
	 * add_entry() in order to actually insert it in the table.
	 */
	virtual std::unique_ptr<table_entry> new_entry() const = 0;

	/**
	 * @brief Iterates over all the entries contained in the table and invokes
	 * the given predicate for each of them.
	 *
	 * @param pred The predicate to invoke for all the table's entries. The
	 * predicate returns true if the iteration can proceed to the next entry,
	 * and false if the iteration needs to break out.
	 * @return true If the iteration proceeded successfully for all the entries.
	 * @return false If the iteration broke out.
	 */
	virtual bool foreach_entry(std::function<bool(table_entry& e)> pred) = 0;

	virtual const ss_plugin_table_fieldinfo* list_fields(sinsp_table_owner* owner,
	                                                     uint32_t* nfields) = 0;

	virtual ss_plugin_table_field_t* get_field(sinsp_table_owner* owner,
	                                           const char* name,
	                                           ss_plugin_state_type data_type) = 0;

	virtual ss_plugin_table_field_t* add_field(sinsp_table_owner* owner,
	                                           const char* name,
	                                           ss_plugin_state_type data_type) = 0;

	virtual const char* get_name(sinsp_table_owner* owner) = 0;

	virtual uint64_t get_size(sinsp_table_owner* owner) = 0;

	virtual ss_plugin_table_entry_t* get_entry(sinsp_table_owner* owner,
	                                           const ss_plugin_state_data* key) = 0;

	virtual void release_table_entry(sinsp_table_owner* owner, ss_plugin_table_entry_t* _e) = 0;

	virtual ss_plugin_bool iterate_entries(sinsp_table_owner* owner,
	                                       ss_plugin_table_iterator_func_t it,
	                                       ss_plugin_table_iterator_state_t* s) = 0;

	virtual ss_plugin_rc clear(sinsp_table_owner* owner) = 0;

	virtual ss_plugin_rc erase_entry(sinsp_table_owner* owner, const ss_plugin_state_data* key) = 0;

	virtual ss_plugin_table_entry_t* create_table_entry(sinsp_table_owner* owner) = 0;

	virtual void destroy_table_entry(sinsp_table_owner* owner, ss_plugin_table_entry_t* _e) = 0;

	virtual ss_plugin_table_entry_t* add_entry(sinsp_table_owner* owner,
	                                           const ss_plugin_state_data* key,
	                                           ss_plugin_table_entry_t* _e) = 0;

	virtual ss_plugin_rc read_entry_field(sinsp_table_owner* owner,
	                                      ss_plugin_table_entry_t* _e,
	                                      const ss_plugin_table_field_t* f,
	                                      ss_plugin_state_data* out) = 0;

	virtual ss_plugin_rc write_entry_field(sinsp_table_owner* owner,
	                                       ss_plugin_table_entry_t* _e,
	                                       const ss_plugin_table_field_t* f,
	                                       const ss_plugin_state_data* in) = 0;

protected:
	const base_table* m_this_ptr;
	std::string m_name;
	typeinfo m_key_info;
	const static_struct::field_infos* m_static_fields;
	std::shared_ptr<dynamic_struct::field_infos> m_dynamic_fields;

	std::vector<ss_plugin_table_fieldinfo> m_field_list;
	std::unordered_map<std::string, sinsp_field_accessor_wrapper*> m_field_accessors;
};

/**
 * @brief Base interfaces for state tables, with strong typing for tables' key.
 */
template<typename KeyType>
class table : public base_table {
	static_assert(std::is_default_constructible<KeyType>(),
	              "table key types must have a default constructor");

public:
	inline table(const std::string& name, const static_struct::field_infos* static_fields):
	        base_table(name, typeinfo::of<KeyType>(), static_fields) {}
	inline table(const std::string& name): table(name, _static_fields()) {}
	virtual ~table() = default;
	inline table(table&&) = default;
	inline table& operator=(table&&) = default;
	inline table(const table& s) = delete;
	inline table& operator=(const table& s) = delete;

	/**
	 * @brief Returns a pointer to an entry present in the table at the given
	 * key. The pointer is owned by the table, and will remain valid up until
	 * the table is destroyed or the entry is removed from the table.
	 *
	 * @param key Key of the entry to be retrieved.
	 * @return std::shared_ptr<table_entry> Pointer to the entry if
	 * present in the table at the given key, and nullptr otherwise.
	 */
	virtual std::shared_ptr<table_entry> get_entry(const KeyType& key) = 0;

	/**
	 * @brief Inserts a new entry in the table with the given key. If another
	 * entry is already present with the same key, it gets replaced. After
	 * insertion, table will be come the owner of the entry's pointer.
	 *
	 * @param key Key of the entry to be added.
	 * @param entry Entry to be added with the given key.
	 * @return std::shared_ptr<table_entry> Non-null pointer to the
	 * newly-added entry, which will remain valid up until the table is
	 * destroyed or the entry is removed from the table.
	 */
	virtual std::shared_ptr<table_entry> add_entry(const KeyType& key,
	                                               std::unique_ptr<table_entry> entry) = 0;

	/**
	 * @brief Removes an entry from the table with the given key.
	 *
	 * @param key Key of the entry to be removed.
	 * @return true If an entry was present at the given key.
	 * @return false If an entry was not present at the given key.
	 */
	virtual bool erase_entry(const KeyType& key) = 0;

private:
	static inline const static_struct::field_infos* _static_fields() {
		static const static_struct::field_infos s_fields{};
		return &s_fields;
	}
};

template<typename KeyType>
class built_in_table : public table<KeyType> {
	using table<KeyType>::table;

	std::shared_ptr<table_entry> get_entry(const KeyType& key) override = 0;

	bool erase_entry(const KeyType& key) override = 0;

	std::shared_ptr<table_entry> add_entry(const KeyType& key,
	                                       std::unique_ptr<table_entry> entry) override = 0;

	const char* get_name(sinsp_table_owner* owner) override;

	uint64_t get_size(sinsp_table_owner* owner) override;

	const ss_plugin_table_fieldinfo* list_fields(sinsp_table_owner* owner,
	                                             uint32_t* nfields) override;

	ss_plugin_table_field_t* get_field(sinsp_table_owner* owner,
	                                   const char* name,
	                                   ss_plugin_state_type data_type) override;

	ss_plugin_table_field_t* add_field(sinsp_table_owner* owner,
	                                   const char* name,
	                                   ss_plugin_state_type data_type) override;

	ss_plugin_table_entry_t* get_entry(sinsp_table_owner* owner,
	                                   const ss_plugin_state_data* key) override;

	void release_table_entry(sinsp_table_owner* owner, ss_plugin_table_entry_t* _e) override;

	ss_plugin_bool iterate_entries(sinsp_table_owner* owner,
	                               ss_plugin_table_iterator_func_t it,
	                               ss_plugin_table_iterator_state_t* s) override;

	ss_plugin_rc clear(sinsp_table_owner* owner) override;

	ss_plugin_rc erase_entry(sinsp_table_owner* owner, const ss_plugin_state_data* key) override;

	ss_plugin_table_entry_t* create_table_entry(sinsp_table_owner* owner) override;

	void destroy_table_entry(sinsp_table_owner* owner, ss_plugin_table_entry_t* _e) override;

	ss_plugin_table_entry_t* add_entry(sinsp_table_owner* owner,
	                                   const ss_plugin_state_data* key,
	                                   ss_plugin_table_entry_t* _e) override;

	ss_plugin_rc read_entry_field(sinsp_table_owner* owner,
	                              ss_plugin_table_entry_t* _e,
	                              const ss_plugin_table_field_t* f,
	                              ss_plugin_state_data* out) override;

	ss_plugin_rc write_entry_field(sinsp_table_owner* owner,
	                               ss_plugin_table_entry_t* _e,
	                               const ss_plugin_table_field_t* f,
	                               const ss_plugin_state_data* in) override;
};

class sinsp_table_owner {
public:
	sinsp_table_owner() = default;
	virtual ~sinsp_table_owner() = default;

	std::string m_last_owner_err;

protected:
	std::list<std::shared_ptr<libsinsp::state::table_entry>>
	        m_accessed_entries;  // using lists for ptr stability
	std::list<libsinsp::state::table_accessor>
	        m_ephemeral_tables;  // note: lists have pointer stability
	std::list<libsinsp::state::sinsp_field_accessor_wrapper>
	        m_accessed_table_fields;  // note: lists have pointer stability

	bool m_ephemeral_tables_clear = false;
	bool m_accessed_entries_clear = false;

	inline void clear_ephemeral_tables() {
		if(m_ephemeral_tables_clear) {
			// quick break-out that prevents us from looping over the
			// whole list in the critical path, in case of no accessed table
			return;
		}
		for(auto& et : m_ephemeral_tables) {
			et.unset();
		}
		m_ephemeral_tables_clear = true;
	}

	inline void clear_accessed_entries() {
		if(m_accessed_entries_clear) {
			// quick break-out that prevents us from looping over the
			// whole list in the critical path
			return;
		}
		for(auto& et : m_accessed_entries) {
			if(et != nullptr) {
				// if we get here, it means that the plugin did not
				// release some of the entries it acquired
				ASSERT(false);
				et.reset();
			};
		}
		m_accessed_entries_clear = true;
	}

public:
	inline libsinsp::state::table_accessor& find_unset_ephemeral_table() {
		m_ephemeral_tables_clear = false;
		for(auto& et : m_ephemeral_tables) {
			if(!et.is_set()) {
				return et;
			}
		}
		return m_ephemeral_tables.emplace_back();
	}

	inline std::shared_ptr<libsinsp::state::table_entry>* find_unset_accessed_table_entry() {
		m_accessed_entries_clear = false;
		for(auto& et : m_accessed_entries) {
			if(et == nullptr) {
				return &et;
			}
		}
		return &m_accessed_entries.emplace_back();
	}
};

};  // namespace state
};  // namespace libsinsp

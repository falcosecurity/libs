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

#include <libsinsp/sinsp_exception.h>
#include <libsinsp/state/static_struct.h>
#include <libsinsp/state/dynamic_struct.h>

#include <functional>
#include <type_traits>
#include <memory>

namespace libsinsp {
namespace state {

/**
 * @brief Base class for entries of a state table.
 */
struct table_entry: public static_struct, dynamic_struct
{
    table_entry(const std::shared_ptr<dynamic_struct::field_infos>& dyn_fields)
        : static_struct(), dynamic_struct(dyn_fields) { }
    virtual ~table_entry() = default;
    table_entry(table_entry&&) = default;
    table_entry& operator = (table_entry&&) = default;
    table_entry(const table_entry& s) = default;
    table_entry& operator = (const table_entry& s) = default;
};

/**
 * @brief Base non-templated interface for state tables, defining
 * type-independent properties common to all tables.
 */
class base_table
{
public:
    base_table(const std::string& name, const typeinfo& key_info,
        const static_struct::field_infos& static_fields)
            : m_name(name),
              m_key_info(key_info), 
              m_static_fields(static_fields),
              m_dynamic_fields(std::make_shared<dynamic_struct::field_infos>()) { }

    virtual ~base_table() = default;
    base_table(base_table&&) = default;
    base_table& operator = (base_table&&) = default;
    base_table(const base_table& s) = delete;
    base_table& operator = (const base_table& s) = delete;

    /**
     * @brief Returns the name of the table.
     */
    inline const std::string& name() const
    {
        return m_name;
    }

    /**
     * @brief Returns the non-null type info about the table's key. 
     */
    inline const typeinfo& key_info() const
    {
        return m_key_info;
    }

    /**
     * @brief Returns the fields metadata list for the static fields defined
     * for the value data type of this table. This fields will be accessible
     * for all the entries of this table.
     */
    virtual const static_struct::field_infos& static_fields() const
    {
        return m_static_fields;
    }

    /**
     * @brief Returns the fields metadata list for the dynamic fields defined
     * for the value data type of this table. This fields will be accessible
     * for all the entries of this table. The returned metadata list can
     * be expended at runtime by adding new dynamic fields, which will then
     * be allocated and accessible for all the present and future entries
     * present in the table.
     */
    virtual std::shared_ptr<dynamic_struct::field_infos> dynamic_fields() const
    {
        return m_dynamic_fields;
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

private:
    std::string m_name;
    typeinfo m_key_info;
    static_struct::field_infos m_static_fields;
    std::shared_ptr<dynamic_struct::field_infos> m_dynamic_fields;
};

/**
 * @brief Base interfaces for state tables, with strong typing for tables' key.
 */
template <typename KeyType>
class table: public base_table
{
    static_assert(std::is_default_constructible<KeyType>(),
        "table key types must have a default constructor");

public:
    table(const std::string& name, const static_struct::field_infos& static_fields)
            : base_table(name, typeinfo::of<KeyType>(), static_fields) {}
    table(const std::string& name): table(name, static_struct::field_infos()) {}
    virtual ~table() = default;
    table(table&&) = default;
    table& operator = (table&&) = default;
    table(const table& s) = delete;
    table& operator = (const table& s) = delete;

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
    virtual std::shared_ptr<table_entry> add_entry(const KeyType& key, std::unique_ptr<table_entry> entry) = 0;

    /**
     * @brief Removes an entry from the table with the given key.
     * 
     * @param key Key of the entry to be removed.
     * @return true If an entry was present at the given key.
     * @return false If an entry was not present at the given key.
     */
    virtual bool erase_entry(const KeyType& key) = 0;
};

}; // state
}; // libsinsp

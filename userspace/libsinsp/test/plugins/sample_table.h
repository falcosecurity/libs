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

#include <libscap/engine/source_plugin/source_plugin_public.h>

#include <cstring>
#include <string>
#include <vector>
#include <memory>
#include <unordered_map>

/**
 * @brief A simple plugin-implemented table with u64 keys used for test purposes.
 */
class sample_table
{
public:
    class entry
    {
    public:
        virtual ~entry()
        {
            // note: makes sure that release_table_entry is invoked consistently
            if (refcount > 0)
            {
                fprintf(stderr, "sample_table: table entry deleted with non-zero refcount %ld\n", refcount);
                exit(1);
            }
            for (auto &p : data)
            {
                delete p;
            }
        }
    private:
        std::vector<ss_plugin_state_data*> data;
        std::vector<std::string> strings;
        uint64_t refcount;

        friend class sample_table;
    };

    sample_table(const std::string& n, std::string& err):
        name(n), lasterr(err), strings(), entries(), fields() { }
    virtual ~sample_table() = default;
    sample_table(sample_table&&) = default;
    sample_table(const sample_table& s) = default;

    static const char* get_name(ss_plugin_table_t* _t)
    {
        auto t = static_cast<sample_table*>(_t);
        return t->name.c_str();
    }

    static uint64_t get_size(ss_plugin_table_t* _t)
    {
        auto t = static_cast<sample_table*>(_t);
        return t->entries.size();
    }

    static const ss_plugin_table_fieldinfo* list_fields(ss_plugin_table_t* _t, uint32_t* nfields)
    {
        auto t = static_cast<sample_table*>(_t);
        *nfields = (uint32_t) t->fields.size();
        return t->fields.data();
    }

    static ss_plugin_table_field_t* get_field(ss_plugin_table_t* _t, const char* name, ss_plugin_state_type data_type)
    {
        auto t = static_cast<sample_table*>(_t);
        for (size_t i = 0; i < t->fields.size(); i++)
        {
            if (strcmp(t->fields[i].name, name) == 0)
            {
                // note: shifted by 1 so that we never return 0 (interpreted as NULL)
                return (ss_plugin_table_field_t*) (i + 1);
            }
        }
        t->lasterr = "unknown field with name: " + std::string(name);
        return nullptr;
    }

    static ss_plugin_table_field_t* add_field(ss_plugin_table_t* _t, const char* name, ss_plugin_state_type data_type)
    {
        auto t = static_cast<sample_table*>(_t);
        for (size_t i = 0; i < t->fields.size(); i++)
        {
            const auto& f = t->fields[i];
            if (strcmp(f.name, name) == 0)
            {
                if (f.field_type != data_type)
                {
                    t->lasterr = "field defined with incompatible types: " + std::string(name);
                    return NULL;
                }
                // note: shifted by 1 so that we never return 0 (interpreted as NULL)
                return (ss_plugin_table_field_t*) (i + 1);
            }
        }

        ss_plugin_table_fieldinfo f;
        t->strings.push_back(name);
        f.field_type = data_type;
        f.read_only = false;
        t->fields.push_back(f);
        for (size_t i = 0; i < t->fields.size(); i++)
        {
            // note: previous string pointers may have been changed so we
            // we need to set all of them again
            t->fields[i].name = t->strings[i].c_str();
        }

        // note: shifted by 1 so that we never return 0 (interpreted as NULL)
        return (ss_plugin_table_field_t*) (t->fields.size());
    }

    static ss_plugin_table_entry_t *get_entry(ss_plugin_table_t *_t, const ss_plugin_state_data *key)
    {
        auto t = static_cast<sample_table*>(_t);
        auto it = t->entries.find(key->u64);
        if (it != t->entries.end())
        {
            it->second.refcount++;
            return static_cast<ss_plugin_table_entry_t*>(&it->second);
        }
        t->lasterr = "unknown entry at key: " + std::to_string(key->u64);
        return nullptr;
    }

    static ss_plugin_rc read_entry_field(ss_plugin_table_t *_t, ss_plugin_table_entry_t *_e, const ss_plugin_table_field_t *_f, ss_plugin_state_data *out)
    {
        auto t = static_cast<sample_table*>(_t);
        auto e = static_cast<sample_table::entry*>(_e);
        auto f = size_t (_f) - 1;
        while (e->data.size() <= f)
        {
            e->data.push_back(new ss_plugin_state_data());
            e->strings.emplace_back();
        }
        if (t->fields[f].field_type == SS_PLUGIN_ST_STRING)
        {
            out->str = e->strings[f].c_str();
        }
        else
        {
            memcpy(out, e->data[f], sizeof(ss_plugin_state_data));
        }
        return SS_PLUGIN_SUCCESS;
    }

    static void release_table_entry(ss_plugin_table_t* _t, ss_plugin_table_entry_t* _e)
    {
        auto e = static_cast<sample_table::entry*>(_e);
        e->refcount--;
    }

	static ss_plugin_bool iterate_entries(ss_plugin_table_t* _t, ss_plugin_table_iterator_func_t it, ss_plugin_table_iterator_state_t* s)
    {
        auto t = static_cast<sample_table*>(_t);
        for (auto& [k, e]: t->entries)
        {
            if (it(s, static_cast<ss_plugin_table_entry_t*>(&e)) != 1)
            {
                return 0;
            }
        }
        return 1;
    }

    static ss_plugin_rc clear(ss_plugin_table_t *_t)
    {
        auto t = static_cast<sample_table*>(_t);
        t->entries.clear();
        return SS_PLUGIN_SUCCESS;
    }

    static ss_plugin_rc erase_entry(ss_plugin_table_t *_t, const ss_plugin_state_data *key)
    {
        auto t = static_cast<sample_table*>(_t);
        auto it = t->entries.find(key->u64);
        if (it != t->entries.end())
        {
            t->entries.erase(key->u64);
            return SS_PLUGIN_SUCCESS;;
        }
        t->lasterr = "unknown entry at key: " + std::to_string(key->u64);
        return SS_PLUGIN_FAILURE;
    }

    static ss_plugin_table_entry_t *create_entry(ss_plugin_table_t *t)
    {
        auto e = new sample_table::entry();
        e->refcount = 1;
        return static_cast<ss_plugin_table_entry_t*>(e);
    }

    static void destroy_entry(ss_plugin_table_t* _t, ss_plugin_table_entry_t* _e)
    {
        auto e = static_cast<sample_table::entry*>(_e);
        e->refcount = 0;
        delete e;
    }

    static ss_plugin_table_entry_t *add_entry(ss_plugin_table_t *_t, const ss_plugin_state_data *key, ss_plugin_table_entry_t *_e)
    {
        auto t = static_cast<sample_table*>(_t);
        auto e = static_cast<sample_table::entry*>(_e);
        e->refcount = 0;
        t->entries.insert({ key->u64, *e });
        delete e;
        t->entries[key->u64].refcount = 1;
        return static_cast<ss_plugin_table_entry_t*>(&t->entries[key->u64]);
    }

    static ss_plugin_rc write_entry_field(ss_plugin_table_t* _t, ss_plugin_table_entry_t* _e, const ss_plugin_table_field_t* _f, const ss_plugin_state_data* in)
    {
        auto t = static_cast<sample_table*>(_t);
        auto e = static_cast<sample_table::entry*>(_e);
        auto f = size_t (_f) - 1;
        while (e->data.size() <= f)
        {
            e->data.push_back(new ss_plugin_state_data());
            e->strings.emplace_back();
        }
        if (t->fields[f].field_type == SS_PLUGIN_ST_STRING)
        {
            e->strings[f] = in->str;
        }
        else
        {
            memcpy(e->data[f], in, sizeof(ss_plugin_state_data));
        }
        return SS_PLUGIN_SUCCESS;
    }

    struct deleter_t
    {
        void operator()(ss_plugin_table_input* t)
        {
            delete static_cast<sample_table*>(t->table);
            delete t;
        }
    };

    using ptr_t = std::unique_ptr<ss_plugin_table_input, deleter_t>;

    static ptr_t create(const std::string& name, std::string& lasterr)
    {
        auto t = new sample_table(name, lasterr);
        ptr_t ret(new ss_plugin_table_input());
        ret->name = t->name.c_str();
        ret->table = t;
        ret->key_type = ss_plugin_state_type::SS_PLUGIN_ST_UINT64;
        ret->reader_ext = &t->reader_vtable;
        ret->writer_ext = &t->writer_vtable;
        ret->fields_ext = &t->fields_vtable;
        ret->fields_ext->list_table_fields = list_fields;
        ret->fields_ext->get_table_field = get_field;
        ret->fields_ext->add_table_field = add_field;
        ret->fields.list_table_fields = ret->fields_ext->list_table_fields;
        ret->fields.get_table_field = ret->fields_ext->get_table_field;
        ret->fields.add_table_field = ret->fields_ext->add_table_field;
        ret->reader_ext->get_table_name = get_name;
        ret->reader_ext->get_table_size = get_size;
        ret->reader_ext->get_table_entry = get_entry;
        ret->reader_ext->read_entry_field = read_entry_field;
        ret->reader_ext->release_table_entry = release_table_entry;
        ret->reader_ext->iterate_entries = iterate_entries;
        ret->reader.get_table_name = ret->reader_ext->get_table_name;
        ret->reader.get_table_size = ret->reader_ext->get_table_size;
        ret->reader.get_table_entry = ret->reader_ext->get_table_entry;
        ret->reader.read_entry_field = ret->reader_ext->read_entry_field;
        ret->writer_ext->clear_table = clear;
        ret->writer_ext->erase_table_entry = erase_entry;
        ret->writer_ext->create_table_entry = create_entry;
        ret->writer_ext->destroy_table_entry = destroy_entry;
        ret->writer_ext->add_table_entry = add_entry;
        ret->writer_ext->write_entry_field = write_entry_field;
        ret->writer.clear_table = ret->writer_ext->clear_table;
        ret->writer.erase_table_entry = ret->writer_ext->erase_table_entry;
        ret->writer.create_table_entry = ret->writer_ext->create_table_entry;
        ret->writer.destroy_table_entry = ret->writer_ext->destroy_table_entry;
        ret->writer.add_table_entry = ret->writer_ext->add_table_entry;
        ret->writer.write_entry_field = ret->writer_ext->write_entry_field;
        return ret;
    }

private:
    std::string name;
    std::string& lasterr;
    std::vector<std::string> strings;
    std::unordered_map<uint64_t, entry> entries;
    std::vector<ss_plugin_table_fieldinfo> fields;
    ss_plugin_table_reader_vtable_ext reader_vtable;
    ss_plugin_table_writer_vtable_ext writer_vtable;
    ss_plugin_table_fields_vtable_ext fields_vtable;
};

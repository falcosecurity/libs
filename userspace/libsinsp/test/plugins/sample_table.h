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

#include <engine/source_plugin/source_plugin_public.h>

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
            for (auto &p : data)
            {
                delete p;
            }
        }
    private:
        std::vector<ss_plugin_state_data*> data;

        friend class sample_table;
    };

    sample_table(const std::string& n):
        name(n), strings(), entries(), fields() { }
    virtual ~sample_table() = default;
    sample_table(sample_table&&) = default;
    sample_table& operator = (sample_table&&) = default;
    sample_table(const sample_table& s) = default;
    sample_table& operator = (const sample_table& s) = default;

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

    static ss_plugin_table_fieldinfo* list_fields(ss_plugin_table_t* _t, uint32_t* nfields)
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
        return nullptr;
    }

    static ss_plugin_table_field_t* add_field(ss_plugin_table_t* _t, const char* name, ss_plugin_state_type data_type)
    {
        auto t = static_cast<sample_table*>(_t);
        t->strings.push_back(name);
        ss_plugin_table_fieldinfo f;
        f.name = t->strings[t->strings.size() - 1].c_str();
        f.field_type = data_type;
        f.read_only = false;
        t->fields.push_back(f);
        // note: shifted by 1 so that we never return 0 (interpreted as NULL)
        return (ss_plugin_table_field_t*) (t->fields.size());
    }

    static ss_plugin_table_entry_t *get_entry(ss_plugin_table_t *_t, const ss_plugin_state_data *key)
    {
        auto t = static_cast<sample_table*>(_t);
        auto it = t->entries.find(key->u64);
        if (it != t->entries.end())
        {
            return static_cast<ss_plugin_table_entry_t*>(&it->second);
        }
        return nullptr;
    }

    static ss_plugin_rc read_entry_field(ss_plugin_table_t *_t, ss_plugin_table_entry_t *_e, const ss_plugin_table_field_t *_f, ss_plugin_state_data *out)
    {
        auto e = static_cast<sample_table::entry*>(_e);
        auto f = size_t (_f) - 1;
        while (e->data.size() <= f)
        {
            e->data.push_back(new ss_plugin_state_data());
        }
        memcpy(out, e->data[f], sizeof(ss_plugin_state_data));
        return SS_PLUGIN_SUCCESS;
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
        return SS_PLUGIN_FAILURE;
    }

    static ss_plugin_table_entry_t *create_entry(ss_plugin_table_t *t)
    {
        return static_cast<ss_plugin_table_entry_t*>(new sample_table::entry());
    }

    static ss_plugin_table_entry_t *add_entry(ss_plugin_table_t *_t, const ss_plugin_state_data *key, ss_plugin_table_entry_t *_e)
    {
        auto t = static_cast<sample_table*>(_t);
        auto e = static_cast<sample_table::entry*>(_e);
        t->entries.insert({ key->u64, *e });
        delete e;
        return &t->entries[key->u64];
    }

    static ss_plugin_rc write_entry_field(ss_plugin_table_t* _t, ss_plugin_table_entry_t* _e, const ss_plugin_table_field_t* _f, const ss_plugin_state_data* in)
    {
        auto e = static_cast<sample_table::entry*>(_e);
        auto f = size_t (_f) - 1;
        while (e->data.size() <= f)
        {
            e->data.push_back(new ss_plugin_state_data());
        }
        memcpy(e->data[f], in, sizeof(ss_plugin_state_data));
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

    static ptr_t create(const std::string& name)
    {
        auto t = new sample_table(name);
        ptr_t ret(new ss_plugin_table_input());
        ret->name = t->name.c_str();
        ret->table = t;
        ret->key_type = ss_plugin_state_type::SS_PLUGIN_ST_UINT64;
        ret->fields.list_table_fields = list_fields;
        ret->fields.get_table_field = get_field;
        ret->fields.add_table_field = add_field;
        ret->read.get_table_name = get_name;
        ret->read.get_table_size = get_size;
        ret->read.get_table_entry = get_entry;
        ret->read.read_entry_field = read_entry_field;
        ret->write.clear_table = clear;
        ret->write.erase_table_entry = erase_entry;
        ret->write.create_table_entry = create_entry;
        ret->write.add_table_entry = add_entry;
        ret->write.write_entry_field = write_entry_field;
        return ret;
    }

private:
    std::string name;
    std::vector<std::string> strings;
    std::unordered_map<uint64_t, entry> entries;
    std::vector<ss_plugin_table_fieldinfo> fields;
};

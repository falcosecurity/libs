/*
Copyright (C) 2022 The Falco Authors.

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

#include <gtest/gtest.h>
#include "state/static_struct.h"
#include "state/dynamic_struct.h"
#include "state/table_registry.h"

TEST(typeinfo, basic_tests)
{
    struct some_unknown_type { };
    ASSERT_ANY_THROW(libsinsp::state::typeinfo::of<some_unknown_type>());
    ASSERT_EQ(libsinsp::state::typeinfo::of<std::string>().size(), sizeof(std::string));
    ASSERT_EQ(libsinsp::state::typeinfo::of<std::string>(), libsinsp::state::typeinfo::of<std::string>());
}

TEST(static_struct, defs_and_access)
{
    struct err_multidef_struct: public libsinsp::state::static_struct
    {
        err_multidef_struct(): m_num(0)
        {
            define_static_field(this, m_num, "num");
            define_static_field(this, m_num, "num");
        }

        uint32_t m_num;
    };

    class sample_struct: public libsinsp::state::static_struct
    {
    public:
        sample_struct(): m_num(0), m_str()
        {
            define_static_field(this, m_num, "num");
            define_static_field(this, m_str, "str", true);
        }

        uint32_t get_num() const { return m_num; }
        void set_num(uint32_t v) { m_num = v; }
        const std::string& get_str() const { return m_str; }
        void set_str(const std::string& v) { m_str = v; }

    private:
        uint32_t m_num;
        std::string m_str;
    };

    struct sample_struct2: public libsinsp::state::static_struct
    {
    public:
        sample_struct2(): m_num(0)
        {
            define_static_field(this, m_num, "num");
        }

        uint32_t m_num;
    };

    // test construction errors
    ASSERT_ANY_THROW(err_multidef_struct());

    sample_struct s;
    const auto& fields = s.static_fields();

    // check field definitions
    auto field_num = fields.find("num");
    auto field_str = fields.find("str");
    ASSERT_EQ(fields.size(), 2);
    ASSERT_EQ(fields, sample_struct().static_fields());

    ASSERT_NE(field_num, fields.end());
    ASSERT_EQ(field_num->second.name(), "num");
    ASSERT_EQ(field_num->second.readonly(), false);
    ASSERT_EQ(field_num->second.info(), libsinsp::state::typeinfo::of<uint32_t>());

    ASSERT_NE(field_str, fields.end());
    ASSERT_EQ(field_str->second.name(), "str");
    ASSERT_EQ(field_str->second.readonly(), true);
    ASSERT_EQ(field_str->second.info(), libsinsp::state::typeinfo::of<std::string>());

    // check field access
    auto acc_num = field_num->second.new_accessor<uint32_t>();
    auto acc_str = field_str->second.new_accessor<std::string>();
    ASSERT_ANY_THROW(field_num->second.new_accessor<uint64_t>());
    ASSERT_ANY_THROW(field_str->second.new_accessor<uint64_t>());

    ASSERT_EQ(s.get_num(), 0);
    ASSERT_EQ(s.get_static_field(acc_num), 0);
    s.set_num(5);
    ASSERT_EQ(s.get_num(), 5);
    ASSERT_EQ(s.get_static_field(acc_num), 5);
    s.set_static_field(acc_num, (uint32_t) 6);
    ASSERT_EQ(s.get_num(), 6);
    ASSERT_EQ(s.get_static_field(acc_num), 6);

    std::string str = "";
    ASSERT_EQ(s.get_str(), str);
    ASSERT_EQ(s.get_static_field(acc_str), str);
    str = "hello";
    s.set_str("hello");
    ASSERT_EQ(s.get_str(), str);
    ASSERT_EQ(s.get_static_field(acc_str), str);
    ASSERT_ANY_THROW(s.set_static_field(acc_str, str)); // readonly

    // illegal access from an accessor created from different definition list
    // note: this should supposedly be checked for and throw an exception,
    // but for now we have no elegant way to do it efficiently.
    // todo(jasondellaluce): find a good way to check for this
    sample_struct2 s2;
    auto acc_num2 = s2.static_fields().find("num")->second.new_accessor<uint32_t>();
    ASSERT_NO_THROW(s.get_static_field(acc_num2));
}

TEST(dynamic_struct, defs_and_access)
{
    auto fields = std::make_shared<libsinsp::state::dynamic_struct::field_infos>();

    struct sample_struct: public libsinsp::state::dynamic_struct
    {
    public:
        sample_struct(const std::shared_ptr<field_infos>& i): dynamic_struct(i) { }
    };

    sample_struct s(fields);
    ASSERT_ANY_THROW(sample_struct(nullptr));
    ASSERT_ANY_THROW(sample_struct(std::shared_ptr<libsinsp::state::dynamic_struct::field_infos>()));

    // check field definitions
    ASSERT_EQ(fields->fields().size(), 0);
    ASSERT_EQ(fields, s.dynamic_fields());

    // adding new fields
    auto field_num = fields->add_field<uint64_t>("num");
    ASSERT_EQ(fields->fields().size(), 1);
    ASSERT_EQ(field_num, fields->fields().find("num")->second);
    ASSERT_EQ(field_num.name(), "num");
    ASSERT_EQ(field_num.info(), libsinsp::state::typeinfo::of<uint64_t>());
    ASSERT_EQ(field_num, fields->add_field<uint64_t>("num"));
    ASSERT_ANY_THROW(fields->add_field<uint32_t>("num"));

    auto field_str = fields->add_field<std::string>("str");
    ASSERT_EQ(fields->fields().size(), 2);
    ASSERT_EQ(field_str, fields->fields().find("str")->second);
    ASSERT_EQ(field_str.name(), "str");
    ASSERT_EQ(field_str.info(), libsinsp::state::typeinfo::of<std::string>());
    ASSERT_EQ(field_str, fields->add_field<std::string>("str"));
    ASSERT_ANY_THROW(fields->add_field<uint32_t>("str"));

    // check field access
    auto acc_num = field_num.new_accessor<uint64_t>();
    auto acc_str = field_str.new_accessor<std::string>();
    ASSERT_ANY_THROW(field_num.new_accessor<uint32_t>());
    ASSERT_ANY_THROW(field_str.new_accessor<uint32_t>());

    ASSERT_EQ(s.get_dynamic_field(acc_num), 0);
    s.set_dynamic_field(acc_num, (uint64_t) 6);
    ASSERT_EQ(s.get_dynamic_field(acc_num), 6);

    ASSERT_EQ(s.get_dynamic_field(acc_str), std::string(""));
    s.set_dynamic_field(acc_str, std::string("hello"));
    ASSERT_EQ(s.get_dynamic_field(acc_str), std::string("hello"));

    // illegal access from an accessor created from different definition list
    auto fields2 = std::make_shared<libsinsp::state::dynamic_struct::field_infos>();
    auto field_num2 = fields2->add_field<uint64_t>("num");
    auto acc_num2 = field_num2.new_accessor<uint64_t>();
    ASSERT_ANY_THROW(s.get_dynamic_field(acc_num2));
}

TEST(table_registry, defs_and_access)
{
    class sample_table: public libsinsp::state::table<uint64_t>
    {
    public:
        sample_table(): table("sample") { }

        size_t entries_count() const override
        {
            return m_entries.size();
        }

        void clear_entries() override
        {
            m_entries.clear();
        }

        std::unique_ptr<libsinsp::state::table_entry> new_entry() const override
        {
            return std::unique_ptr<libsinsp::state::table_entry>(
                new libsinsp::state::table_entry(dynamic_fields()));
        }

        bool foreach_entry(std::function<bool(libsinsp::state::table_entry& e)> pred) override
        {
            for (const auto& e : m_entries)
            {
                if (!pred(*e.second.get()))
                {
                    return false;
                }
            }
            return true;
        }

        std::shared_ptr<libsinsp::state::table_entry> get_entry(const uint64_t& key) override
        {
            const auto& it = m_entries.find(key);
            if (it == m_entries.end())
            {
                return nullptr;
            }
            return it->second;
        }

        std::shared_ptr<libsinsp::state::table_entry> add_entry(const uint64_t& key, std::unique_ptr<libsinsp::state::table_entry> entry) override
        {
            m_entries[key] = std::move(entry);
            return m_entries[key];
        }

        bool erase_entry(const uint64_t& key) override
        {
            return m_entries.erase(key) != 0;
        }

    private:
        std::unordered_map<uint64_t, std::shared_ptr<libsinsp::state::table_entry>> m_entries;
    };

    libsinsp::state::table_registry r;
    ASSERT_EQ(r.tables().size(), 0);
    ASSERT_EQ(r.get_table<uint64_t>("sample"), nullptr);
    ASSERT_ANY_THROW(r.add_table<uint64_t>(nullptr));

    sample_table t;
    r.add_table(&t);
    ASSERT_EQ(r.tables().size(), 1);
    ASSERT_EQ(r.tables().find("sample")->second, &t);
    ASSERT_EQ(r.get_table<uint64_t>("sample"), &t);
    ASSERT_ANY_THROW(r.add_table(&t)); // double registration
    ASSERT_ANY_THROW(r.get_table<int>("sample")); // bad key type
}

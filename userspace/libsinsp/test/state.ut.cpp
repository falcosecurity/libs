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
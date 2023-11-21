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

#include <libsinsp/state/type_info.h>

#include <string>
#include <unordered_map>
#include <memory>

namespace libsinsp {
namespace state {

/**
 * @brief A base class for classes and structs that allow dynamic programming
 * by being extensible and allowing adding and accessing new data fields at runtime. 
 */
class dynamic_struct
{
public:
    template<typename T> class field_accessor;

    /**
     * @brief Info about a given field in a dynamic struct.
     */
    class field_info
    {
    public:
        template<typename T>
        static field_info build(const std::string& name, size_t index, void* defsptr, bool readonly=false)
        {
            return field_info(name, index, libsinsp::state::typeinfo::of<T>(), defsptr, readonly);
        }

        field_info(const std::string& n, size_t in, const typeinfo& i, void* defsptr, bool r)
            : m_readonly(r),
              m_index(in),
              m_name(n),
              m_info(i),
              m_defsptr(defsptr) {}
        field_info():
            m_readonly(true),
            m_index((size_t) -1),
            m_name(""),
            m_info(typeinfo::of<uint8_t>()),
            m_defsptr(NULL) {}
        ~field_info() = default;
        field_info(field_info&&) = default;
        field_info& operator = (field_info&&) = default;
        field_info(const field_info& s) = default;
        field_info& operator = (const field_info& s) = default;

        friend inline bool operator==(const field_info& a, const field_info& b)
        {
            return a.info() == b.info()
                && a.name() == b.name()
                && a.m_index == b.m_index
                && a.m_defsptr == b.m_defsptr;
        };

        friend inline bool operator!=(const field_info& a, const field_info& b)
        {
            return !(a == b);
        };

        /**
         * @brief Returns true if the field is read only.
         */
        bool readonly() const
        {
            return m_readonly;
        }

        /**
         * @brief Returns true if the field info is valid.
         */
        inline bool valid() const
        {
            return m_index != (size_t) -1;
        }

        /**
         * @brief Returns the name of the field.
         */
        const std::string& name() const
        {
            return m_name;
        }

        /**
         * @brief Returns the index of the field.
         */
        size_t index() const
        {
            return m_index;
        }

        /**
         * @brief Returns the type info of the field.
         */
        const libsinsp::state::typeinfo& info() const
        {
            return m_info;
        }

        /**
         * @brief Returns a strongly-typed accessor for the given field,
         * that can be used to reading and writing the field's value in
         * all instances of structs where it is defined.
         */
        template <typename T>
        field_accessor<T> new_accessor() const
        {
            if (!valid())
            {
                throw sinsp_exception("can't create dynamic struct field accessor for invalid field");
            }
            auto t = libsinsp::state::typeinfo::of<T>();
            if (m_info != t)
            {
                throw sinsp_exception(
                    "incompatible type for dynamic struct field accessor: field=" + m_name
                    + ", expected_type=" + t.name() + ", actual_type=" + m_info.name());
            }
            return field_accessor<T>(*this);
        }

    private:
        bool m_readonly;
        size_t m_index;
        std::string m_name;
        libsinsp::state::typeinfo m_info;
        void* m_defsptr;

        friend class dynamic_struct;
    };

    /**
     * @brief An strongly-typed accessor for accessing a field of a dynamic struct.
     * @tparam T Type of the field.
     */
    template<typename T>
    class field_accessor
    {
    public:
        field_accessor() = default;
        ~field_accessor() = default;
        field_accessor(field_accessor&&) = default;
        field_accessor& operator = (field_accessor&&) = default;
        field_accessor(const field_accessor& s) = default;
        field_accessor& operator = (const field_accessor& s) = default;

        /**
         * @brief Returns the info about the field to which this accessor is tied.
         */
        const field_info& info() const
        {
            return m_info;
        }

    private:
        field_accessor(const field_info& info): m_info(info) { };

        field_info m_info;

        friend class dynamic_struct;
        friend class dynamic_struct::field_info;
    };

    /**
     * @brief Dynamic fields metadata of a given struct or class
     * that are discoverable and accessible dynamically at runtime.
     * All instances of the same struct or class must share the same
     * instance of field_infos.
     */
    class field_infos
    {
    public:
        field_infos() = default;
        virtual ~field_infos() = default;
        field_infos(field_infos&&) = default;
        field_infos& operator = (field_infos&&) = default;
        field_infos(const field_infos& s) = delete;
        field_infos& operator = (const field_infos& s) = delete;

        /**
         * @brief Adds metadata for a new field to the list. An exception is
         * thrown if two fields are defined with the same name and with
         * incompatible types, otherwise the previous definition is returned.
         * 
         * @tparam T Type of the field.
         * @param name Display name of the field.
         */
        template<typename T>
        inline const field_info& add_field(const std::string& name)
        {
            auto field = field_info::build<T>(name, m_definitions.size(), this);
            return add_field(field);
        }

        virtual const std::unordered_map<std::string, field_info>& fields()
        {
            return m_definitions;
        }

protected:
        virtual const field_info& add_field(const field_info& field)
        {
            const auto &it = m_definitions.find(field.name());
            if (it != m_definitions.end())
            {
                const auto& t = field.info();
                if (it->second.info() != t)
                {
                    throw sinsp_exception("multiple definitions of dynamic field with different types in struct: "
                    + field.name() + ", prevtype=" + it->second.info().name() + ", newtype=" + t.name());
                }
                return it->second;
            }
            m_definitions.insert({ field.name(), field });
            const auto& def = m_definitions.at(field.name());
            m_definitions_ordered.push_back(&def);
            return def;
        }

        std::unordered_map<std::string, field_info> m_definitions;
        std::vector<const field_info*> m_definitions_ordered;
        friend class dynamic_struct;
    };

    dynamic_struct(const std::shared_ptr<field_infos>& dynamic_fields)
        : m_fields_len(0), m_fields(), m_dynamic_fields(dynamic_fields) { }
    dynamic_struct(dynamic_struct&&) = default;
    dynamic_struct& operator = (dynamic_struct&&) = default;
    dynamic_struct(const dynamic_struct& s) = default;
    dynamic_struct& operator = (const dynamic_struct& s) = default;
    virtual ~dynamic_struct()
    {
        if (m_dynamic_fields)
        {
            for (size_t i = 0; i < m_fields.size(); i++)
            {
                m_dynamic_fields->m_definitions_ordered[i]->info().destroy(m_fields[i]);
                free(m_fields[i]);
            }
        }
    }

    /**
     * @brief Accesses a field with the given accessor and reads its value.
     */
    template <typename T, typename Val = T>
    inline void get_dynamic_field(const field_accessor<T>& a, Val& out)
    {
        _check_defsptr(a.info(), false);
        get_dynamic_field(a.info(), reinterpret_cast<void*>(&out));
    }

    /**
     * @brief Accesses a field with the given accessor and writes its value.
     */
    template <typename T, typename Val = T>
    inline void set_dynamic_field(const field_accessor<T>& a, const Val& in)
    {
        _check_defsptr(a.info(), true);
        if (a.info().readonly())
        {
            throw sinsp_exception("can't set a read-only dynamic struct field: " + a.info().name());
        }
        set_dynamic_field(a.info(), reinterpret_cast<const void*>(&in));
    }

    /**
     * @brief Returns information about all the dynamic fields accessible in a struct.
     */
    inline const std::shared_ptr<field_infos>& dynamic_fields() const
    {
        return m_dynamic_fields;
    }

    /**
     * @brief Sets the shared definitions for the dynamic fields accessible in a struct.
     * The definitions can be set to a non-null value only once, either at
     * construction time by invoking this method.
     */
    virtual void set_dynamic_fields(const std::shared_ptr<field_infos>& defs)
    {
        if (m_dynamic_fields)
        {
            throw sinsp_exception("dynamic struct defintions set twice");
        }
        if (!defs)
        {
            throw sinsp_exception("dynamic struct constructed with null field definitions");
        }
        m_dynamic_fields = defs;
    }

protected:
    /**
     * @brief Gets the value of a dynamic field and writes it into "out".
     * "out" points to a variable having the type of the field_info argument,
     * according to the type definitions supported in libsinsp::state::typeinfo.
     * For strings, "out" is considered of type const char**.
    */
    virtual void get_dynamic_field(const field_info& i, void* out)
    {
        const auto* buf = _access_dynamic_field(i.m_index);
        if (i.info().index() == PT_CHARBUF)
        {
            *((const char**) out) = ((const std::string*) buf)->c_str();
        }
        else
        {
            memcpy(out, buf, i.info().size());
        }
    }

    /**
     * @brief Sets the value of a dynamic field by reading it from "in".
     * "in" points to a variable having the type of the field_info argument,
     * according to the type definitions supported in libsinsp::state::typeinfo.
     * For strings, "in" is considered of type const char**.
    */
    virtual void set_dynamic_field(const field_info& i, const void* in)
    {
        auto* buf = _access_dynamic_field(i.m_index);
        if (i.info().index() == PT_CHARBUF)
        {
            *((std::string*) buf) = *((const char**) in);
        }
        else
        {
            memcpy(buf, in, i.info().size());
        }
    }

private:
    inline void _check_defsptr(const field_info& i, bool write) const
    {
        if (!i.valid())
        {
            throw sinsp_exception("can't set invalid field in dynamic struct");
        }
        if (m_dynamic_fields.get() != i.m_defsptr)
        {
            throw sinsp_exception("using dynamic field accessor on struct it was not created from");
        }
        if (write && i.readonly())
        {
            throw sinsp_exception("can't set a read-only dynamic struct field: " + i.name());
        }
    }

    inline void* _access_dynamic_field(size_t index)
    {
        if (!m_dynamic_fields)
        {
            throw sinsp_exception("dynamic struct has no field definitions");
        }
        if (index >= m_dynamic_fields->m_definitions_ordered.size())
        {
            throw sinsp_exception("dynamic struct access overflow: " + std::to_string(index));
        }
        while (m_fields_len <= index)
        {
            auto def = m_dynamic_fields->m_definitions_ordered[m_fields_len];
            void* fieldbuf = malloc(def->info().size());
            def->info().construct(fieldbuf);
            m_fields.push_back(fieldbuf);
            m_fields_len++;
        }
        return m_fields[index];
    }

    size_t m_fields_len;
    std::vector<void*> m_fields;
    std::shared_ptr<field_infos> m_dynamic_fields;
};


}; // state
}; // libsinsp

// specializations for string types

template<> inline void libsinsp::state::dynamic_struct::get_dynamic_field<std::string,const char*>(
    const field_accessor<std::string>& a, const char*& out)
{
    _check_defsptr(a.info(), false);
    get_dynamic_field(a.info(), reinterpret_cast<void*>(&out));
}

template<> inline void libsinsp::state::dynamic_struct::get_dynamic_field<std::string,std::string>(
    const field_accessor<std::string>& a, std::string& out)
{
    const char* s = NULL;
    get_dynamic_field(a, s);
    if (!s)
    {
        out.clear();
    }
    else
    {
        out = s;
    }
}

template <> inline void libsinsp::state::dynamic_struct::set_dynamic_field<std::string,const char*>(
    const field_accessor<std::string>& a, const char* const& in)
{
    _check_defsptr(a.info(), true);
    set_dynamic_field(a.info(), reinterpret_cast<const void*>(&in));
}

template <> inline void libsinsp::state::dynamic_struct::set_dynamic_field<std::string,std::string>(
    const field_accessor<std::string>& a, const std::string& in)
{
    set_dynamic_field(a, in.c_str());
}

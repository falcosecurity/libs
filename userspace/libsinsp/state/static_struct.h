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

#include "type_info.h"

#include <string>
#include <unordered_map>

namespace libsinsp {
namespace state {

/**
 * @brief A base class for classes and structs that allow dynamic programming
 * by making part (or all) of their fields discoverable and accessible at runtime.
 * The structure of the class is predetermined at compile-time and its fields
 * are placed at a given offset within the class memory area.
 */
class static_struct
{
public:
    template<typename T> class field_accessor;

    /**
     * @brief Info about a given field in a static struct.
     */
    class field_info
    {
    public:
        field_info() = delete;
        ~field_info() = default;
        field_info(field_info&&) = default;
        field_info& operator = (field_info&&) = default;
        field_info(const field_info& s) = default;
        field_info& operator = (const field_info& s) = default;

        friend inline bool operator==(const field_info& a, const field_info& b)
        {
            return a.info() == b.info()
                && a.name() == b.name()
                && a.readonly() == b.readonly()
                && a.m_offset == b.m_offset;
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
         * @brief Returns the name of the field.
         */
        const std::string& name() const
        {
            return m_name;
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
            auto t = libsinsp::state::typeinfo::of<T>();
            if (m_info != t)
            {
                throw sinsp_exception(
                    "incompatible type for static struct field accessor: field=" + m_name
                    + ", expected_type=" + info().name() + ", actual_type=" + t.name());
            }
            return field_accessor<T>(*this);
        }

    private:
        field_info(const std::string& n, size_t o, const typeinfo& i, bool r)
            : m_readonly(r),
              m_offset(o),
              m_name(n),
              m_info(i) { }
        
        template<typename T>
        static field_info _build(const std::string& name, size_t offset, bool readonly=false)
        {
            return field_info(name, offset, libsinsp::state::typeinfo::of<T>(), readonly);
        }

        bool m_readonly;
        size_t m_offset;
        std::string m_name;
        libsinsp::state::typeinfo m_info;

        friend class static_struct;
    };

    /**
     * @brief An strongly-typed accessor for accessing a field of a static struct.
     * @tparam T Type of the field.
     */
    template<typename T>
    class field_accessor
    {
    public:
        field_accessor() = delete;
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

        friend class static_struct;
        friend class static_struct::field_info;
    };

    /**
     * @brief A group of field infos, describing all the ones available
     * in a static struct.
     */
    using field_infos = std::unordered_map<std::string, field_info>;

    static_struct() = default;
    virtual ~static_struct() = default;
    static_struct(static_struct&&) = default;
    static_struct& operator = (static_struct&&) = default;
    static_struct(const static_struct& s) = default;
    static_struct& operator = (const static_struct& s) = default;

    /**
     * @brief Accesses a field with the given accessor and reads its value.
     */
    template <typename T>
    inline T& get_static_field(const field_accessor<T>& a) const
    {
        return *(reinterpret_cast<T*>((void*) (((uintptr_t) this) + a.info().m_offset)));
    }

    /**
     * @brief Accesses a field with the given accessor and writes its value.
     * An exception is thrown if the field is read-only.
     */
    template <typename T>
    inline void set_static_field(const field_accessor<T>& a, const T& v)
    {
        if (a.info().readonly())
        {
            throw sinsp_exception("can't set a read-only static struct field: " + a.info().name());
        }
        *(reinterpret_cast<T*>((void*) (((uintptr_t) this) + a.info().m_offset))) = v;
    }

    /**
     * @brief Returns information about all the static fields accessible in a struct.
     */
    inline const field_infos& static_fields() const
    {
        return m_static_fields;
    }

protected:
    /**
     * @brief To be used in the constructor of child classes.
     * Defines the information about a field defined in the class or struct.
     * An exception is thrown if two fields are defined with the same name.
     * 
     * @tparam T Type of the field.
     * @param thisptr "this" pointer of the struct containing the field,
     * which is used to compute the field's memory offset in other instances
     * of the same struct.
     * @param v Reference to the field of which info is defined.
     * @param name Display name of the field.
     */
    template<typename T>
    const field_info& define_static_field(const void* thisptr, const T& v, const std::string& name, bool readonly=false)
    {
        const auto &it = m_static_fields.find(name);
        if (it != m_static_fields.end())
        {
            throw sinsp_exception("multiple definitions of static field in struct: " + name);
        }

        // todo(jasondellaluce): add extra safety boundary checks here
        size_t offset = (size_t) (((uintptr_t) &v) - (uintptr_t) thisptr);
        m_static_fields.insert({ name, field_info::_build<T>(name, offset, readonly) });
        return m_static_fields.at(name);
    }

private:
    field_infos m_static_fields;
};


}; // state
}; // libsinsp

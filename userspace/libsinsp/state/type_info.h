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
#include <driver/ppm_events_public.h>

#include <string>
#include <vector>

namespace libsinsp {
namespace state {

/**
 * @brief Generic and agnostic information about a type, similar to
 * std::type_info but following a restricted and controlled enumeration of
 * the supported types for the state component of libsinsp. Enumerating
 * the types also allows for more peformant runtime checks. Moreover, this class
 * also provides construction and destruction utilities for each supported
 * types for convenience.
 */
class typeinfo
{
public:
    /**
     * @brief Numeric identifier of a supported type.
     * This reuses the same type enumerative provided by libscap for event
     * params to avoid duplicating definitions.
     */
    using index_t = ppm_param_type;

    /**
     * @brief Returns a type info for the type T.
     */
    template<typename T> static inline typeinfo of()
    {
        throw sinsp_exception("state::typeinfo::of invoked for unsupported type");
    }

    typeinfo() = delete;
    ~typeinfo() = default;
    typeinfo(typeinfo&&) = default;
    typeinfo& operator = (typeinfo&&) = default;
    typeinfo(const typeinfo& s) = default;
    typeinfo& operator = (const typeinfo& s) = default;

    friend inline bool operator==(const typeinfo& a, const typeinfo& b)
    {
        return a.index() == b.index();
    };

    friend inline bool operator!=(const typeinfo& a, const typeinfo& b)
    {
        return a.index() != b.index();
    };

    /**
     * @brief Returns the name of the type.
     */
    inline const char* name() const
    {
        return m_name;
    }

    /**
     * @brief Returns the numeric representation of the type.
     */
    inline index_t index() const
    {
        return m_index;
    }

    /**
     * @brief Returns the byte size of variables of the given type.
     */
    inline size_t size() const
    {
        return m_size;
    }

    /**
     * @brief Constructs and initializes the given type in the passed-in
     * memory location, which is expected to be larger or equal than size().
     */
    inline void construct(void* p) const noexcept 
    {
        if (p && m_construct) m_construct(p);
    }

    /**
     * @brief Destructs and deinitializes the given type in the passed-in
     * memory location, which is expected to be larger or equal than size().
     */
    inline void destroy(void* p) const noexcept 
    {
        if (p && m_destroy) m_destroy(p);
    }

private:
    inline typeinfo(const char* n, index_t k, size_t s, void (*c)(void*), void (*d)(void*))
        : m_name(n), m_index(k), m_size(s), m_construct(c), m_destroy(d) { }

    template <typename T, typename _Alloc = std::allocator<T>> static inline void _construct(void* p)
    {
        _Alloc a;
        std::allocator_traits<_Alloc>::construct(a, reinterpret_cast<T*>(p));
    }

    template <typename T, typename _Alloc = std::allocator<T>> static inline void _destroy(void* p)
    {
        _Alloc a;
        std::allocator_traits<_Alloc>::destroy(a, reinterpret_cast<T*>(p));
    }

    template<typename T> static inline typeinfo _build(const char* n, index_t k)
    {
        return typeinfo(n, k, sizeof(T), _construct<T>, _destroy<T>);
    }

    const char* m_name;
    index_t m_index;
    size_t m_size;
    void (*m_construct)(void*);
    void (*m_destroy)(void*);
};

// below is the manually-controlled list of all the supported types

template<> inline typeinfo typeinfo::of<bool>() { return _build<bool>("bool", PT_BOOL); }
template<> inline typeinfo typeinfo::of<int8_t>() { return _build<int8_t>("int8", PT_INT8); }
template<> inline typeinfo typeinfo::of<int16_t>() { return _build<int16_t>("int16", PT_INT16); }
template<> inline typeinfo typeinfo::of<int32_t>() { return _build<int32_t>("int32", PT_INT32); }
template<> inline typeinfo typeinfo::of<int64_t>() { return _build<int64_t>("int64", PT_INT64); }
template<> inline typeinfo typeinfo::of<uint8_t>() { return _build<uint8_t>("uint8", PT_UINT8); }
template<> inline typeinfo typeinfo::of<uint16_t>() { return _build<uint16_t>("uint16", PT_UINT16); }
template<> inline typeinfo typeinfo::of<uint32_t>() { return _build<uint32_t>("uint32", PT_UINT32); }
template<> inline typeinfo typeinfo::of<uint64_t>() { return _build<uint64_t>("uint64", PT_UINT64); }
template<> inline typeinfo typeinfo::of<std::string>() { return _build<std::string>("string", PT_CHARBUF); }

}; // state
}; // libsinsp

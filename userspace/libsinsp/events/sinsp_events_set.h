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

#include <libsinsp/event.h>
#include <libsinsp/sinsp_exception.h>
#include <libsinsp/sinsp_public.h>

#include <vector>
#include <functional>
#include <initializer_list>
#include <iterator>
#include <cstddef>

// The following are needed on MacOS to be able to
// initialize a std::(unordered)map/set<ppm_X_code>{}
namespace std
{
template<>
struct hash<ppm_sc_code> {
	size_t operator()(const ppm_sc_code &pt) const {
		return std::hash<uint32_t>()((uint32_t)pt);
	}
};

template<>
struct hash<ppm_event_code> {
	size_t operator()(const ppm_event_code &pt) const {
		return std::hash<uint32_t>()((uint32_t)pt);
	}
};
}

namespace libsinsp {
namespace events {

template<typename T>
class set
{
private:
	using vec_t = std::vector<uint8_t>;
	vec_t m_types{};
	T m_max;
	size_t m_size;

	inline void check_range(T e) const
	{
		if(e > m_max)
		{
			throw sinsp_exception("invalid event type");
		}
	}

public:
	struct iterator
	{
		using iterator_category = std::forward_iterator_tag;
		using difference_type   = std::ptrdiff_t;
		using value_type        = T;
		using pointer           = T*;
		using reference         = T&;

		iterator(const uint8_t* data, size_t index, size_t max)
			: m_data(data), m_index(index), m_max(max)
		{
			set_val();
		}
		reference operator*() { return m_val; }
		pointer operator->() { return &m_val; }
		iterator& operator++() { m_index++; set_val(); return *this; }
		iterator operator++(int) { iterator i = *this; ++(*this); return i; }
		friend bool operator== (const iterator& a, const iterator& b)
		{
			return a.m_data == b.m_data && a.m_index == b.m_index;
		};
		friend bool operator!= (const iterator& a, const iterator& b) { return !(a == b); };
	private:
		inline void set_val()
		{
			while (m_index < m_max && m_data[m_index] == 0)
			{
				m_index++;
			}
			m_val = (value_type) m_index;
		}

		const uint8_t* m_data;
		size_t m_index;
		size_t m_max;
		value_type m_val;
	};

	set(set&&) noexcept = default;
	set(const set&) = default;
	set& operator=(set&&) noexcept = default;
	set& operator=(const set&) = default;
	set() = delete;

	template<typename InputIterator>
	static set<T> from(InputIterator first, InputIterator last)
	{
		set<T> ret;
		for (auto i = first; i != last; i++)
		{
			ret.insert(*i);
		}
		return ret;
	}

	template<typename Iterable>
	static set<T> from(const Iterable& v)
	{
		return from(v.begin(), v.end());
	}

	template<typename Iterable>
	set(const Iterable& v): set(from(v)) { }

	template<typename InputIterator>
	set(InputIterator first, InputIterator last): set(from(first, last)) { }

	set(std::initializer_list<T> v): set(v.begin(), v.end()) { }

	inline explicit set(T maxLen):
		m_types(maxLen + 1, 0),
		m_max(maxLen),
		m_size(0)
	{
	}

	const uint8_t* data() const noexcept
	{
		return m_types.data();
	}

	iterator begin() const { return iterator(m_types.data(), 0, m_max); }
	iterator end() const { return iterator(m_types.data(), m_max, m_max); }

	inline void insert(T e)
	{
		check_range(e);
		if (m_types[e] == 0)
		{
			m_size++;
		}
		m_types[e] = 1;
	}

	template<typename InputIterator>
	inline void insert(InputIterator first, InputIterator last)
	{
		for (auto i = first; i != last; i++)
		{
			insert(*i);
		}
	}

	inline void remove(T e)
	{
		check_range(e);
		if (m_types[e] == 1)
		{
			m_size--;
		}
		m_types[e] = 0;
	}

	inline bool contains(T e) const
	{
		check_range(e);
		return m_types[e] != 0;
	}

	void clear()
	{
		for(auto& v : m_types)
		{
			v = 0;
		}
		m_size = 0;
	}

	inline bool empty() const
	{
		return m_size == 0;
	}

	inline size_t size() const
	{
		return m_size;
	}

	bool equals(const set& other) const
	{
		return m_types == other.m_types;
	}

	set merge(const set& other) const
	{
		if (other.m_max != m_max)
		{
			throw sinsp_exception("cannot merge sets with different max size.");
		}
		set<T> ret(m_max);
		for(size_t i = 0; i <= m_max; ++i)
		{
			if (m_types[i] | other.m_types[i])
			{
				ret.insert((T)i);
			}
		}
		return ret;
	}

	set diff(const set& other) const
	{
		if (other.m_max != m_max)
		{
			throw sinsp_exception("cannot diff sets with different max size.");
		}
		set<T> ret(m_max);
		for(size_t i = 0; i <= m_max; ++i)
		{
			if (m_types[i] == 1 && other.m_types[i] == 0)
			{
				ret.insert((T)i);
			}
		}
		return ret;
	}

	set intersect(const set& other) const
	{
		if (other.m_max != m_max)
		{
			throw sinsp_exception("cannot intersect sets with different max size.");
		}
		set<T> ret(m_max);
		for(size_t i = 0; i <= m_max; ++i)
		{
			if (m_types[i] & other.m_types[i])
			{
				ret.insert((T)i);
			}
		}
		return ret;
	}

	void for_each(const std::function<bool(T)>& consumer) const
	{
		for(size_t i = 0; i < m_max; ++i)
		{
			if(m_types[i] != 0)
			{
				if(!consumer((T) i))
				{
					return;
				}
			}
		}
	}

	set filter(const std::function<bool(T)>& predicate) const
	{
		set<T> ret;
		for_each([&ret, &predicate](T v){
			if(predicate(v))
			{
				ret.insert(v);
			}
			return true;
		});
		return ret;
	}
};

// Some template specialization for useful constructors

template <>
inline set<ppm_sc_code>::set(): set(PPM_SC_MAX)
{
}

template<>
inline set<ppm_event_code>::set(): set(PPM_EVENT_MAX)
{
}

} // events
} // libsinsp

template<typename T>
inline bool operator==(const libsinsp::events::set<T>& lhs, const libsinsp::events::set<T>& rhs)
{
	return lhs.equals(rhs);
}

template<typename T>
inline bool operator!=(const libsinsp::events::set<T>& lhs, const libsinsp::events::set<T>& rhs)
{
	return !(lhs == rhs);
}

template<typename T>
std::ostream& operator<<(std::ostream& os, const libsinsp::events::set<T>& s)
{
	os << "(";
	auto first = true;
	for (const auto& v : s)
	{
		os << (first ? "" : ", ") << v;
		first = false;
	}
	os << ")";
	return os;
}

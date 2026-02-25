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

#include <functional>
#include <memory>
#include <unordered_map>

#include <libsinsp/threadinfo.h>

#ifdef LIBSINSP_USE_FOLLY
#include <folly/concurrency/ConcurrentHashMap.h>
#endif

/** Thread table storage: concurrent (Folly) when LIBSINSP_USE_FOLLY, else std::unordered_map. */
class threadinfo_map_t {
public:
	typedef std::function<bool(const std::shared_ptr<sinsp_threadinfo>&)>
	        const_shared_ptr_visitor_t;
	typedef std::function<bool(const sinsp_threadinfo&)> const_visitor_t;
	typedef std::function<bool(sinsp_threadinfo&)> visitor_t;
	typedef std::shared_ptr<sinsp_threadinfo> ptr_t;

	inline ptr_t put(const ptr_t& tinfo) {
#ifdef LIBSINSP_USE_FOLLY
		auto [it, _] = m_threads.insert_or_assign(tinfo->m_tid, tinfo);
		return it->second;
#else
		m_threads[tinfo->m_tid] = tinfo;
		return m_threads[tinfo->m_tid];
#endif
	}

	inline sinsp_threadinfo* get(uint64_t tid) {
#ifdef LIBSINSP_USE_FOLLY
		auto it = m_threads.find(tid);
		if(it == m_threads.end()) {
			return nullptr;
		}
		return it->second.get();
#else
		auto it = m_threads.find(tid);
		if(it == m_threads.end()) {
			return nullptr;
		}
		return it->second.get();
#endif
	}

	inline ptr_t get_ref(uint64_t tid) {
#ifdef LIBSINSP_USE_FOLLY
		auto it = m_threads.find(tid);
		if(it == m_threads.end()) {
			return {};
		}
		return it->second;
#else
		auto it = m_threads.find(tid);
		if(it == m_threads.end()) {
			return {};
		}
		return it->second;
#endif
	}

	inline void erase(uint64_t tid) { m_threads.erase(tid); }

	inline void clear() { m_threads.clear(); }

	bool const_loop_shared_pointer(const_shared_ptr_visitor_t callback) {
#ifdef LIBSINSP_USE_FOLLY
		for(auto it = m_threads.begin(); it != m_threads.end(); ++it) {
			if(!callback(it->second)) {
				return false;
			}
		}
		return true;
#else
		for(auto& it : m_threads) {
			if(!callback(it.second)) {
				return false;
			}
		}
		return true;
#endif
	}

	bool const_loop_shared_pointer(const_shared_ptr_visitor_t callback) const {
#ifdef LIBSINSP_USE_FOLLY
		for(auto it = m_threads.cbegin(); it != m_threads.cend(); ++it) {
			if(!callback(it->second)) {
				return false;
			}
		}
		return true;
#else
		for(const auto& it : m_threads) {
			if(!callback(it.second)) {
				return false;
			}
		}
		return true;
#endif
	}

	bool const_loop(const_visitor_t callback) const {
#ifdef LIBSINSP_USE_FOLLY
		for(auto it = m_threads.cbegin(); it != m_threads.cend(); ++it) {
			if(!callback(*it->second)) {
				return false;
			}
		}
		return true;
#else
		for(const auto& it : m_threads) {
			if(!callback(*it.second)) {
				return false;
			}
		}
		return true;
#endif
	}

	bool loop(visitor_t callback) {
#ifdef LIBSINSP_USE_FOLLY
		for(auto it = m_threads.begin(); it != m_threads.end(); ++it) {
			if(!callback(*it->second)) {
				return false;
			}
		}
		return true;
#else
		for(auto& it : m_threads) {
			if(!callback(*it.second)) {
				return false;
			}
		}
		return true;
#endif
	}

	inline size_t size() const { return m_threads.size(); }

protected:
#ifdef LIBSINSP_USE_FOLLY
	folly::ConcurrentHashMap<int64_t, ptr_t> m_threads;
#else
	std::unordered_map<int64_t, ptr_t> m_threads;
#endif
};

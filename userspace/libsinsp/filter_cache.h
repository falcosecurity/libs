// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

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
#include <libsinsp/filter_field.h>
#include <libsinsp/filter_compare.h>
#include <libsinsp/filter/ast.h>

#include <cstdint>
#include <vector>

/**
 * @brief Represents a value extracted when evaluating a filter
 */
struct extract_value_t {
	uint8_t* ptr = nullptr;
	uint32_t len = 0;
};

/**
 * @brief Represents a field offset extracted when evaluating a filter
 */
struct extract_offset_t {
	uint32_t start = 1;
	uint32_t end = 0;
};

/**
 * @brief Represents a cache value storage for value extraction in filters
 */
class sinsp_filter_extract_cache {
public:
	inline void reset() { m_evtnum = UINT64_MAX; }

	inline bool is_valid(const sinsp_evt* evt) const {
		return evt->get_num() != 0 && m_evtnum != UINT64_MAX && evt->get_num() == m_evtnum;
	}

	inline void update(const sinsp_evt* evt,
	                   bool res,
	                   const std::vector<extract_value_t>& values,
	                   bool deepcopy = false) {
		m_evtnum = evt->get_num();
		m_result = res;
		if(!deepcopy) {
			m_values = values;
			return;
		}

		auto len = m_values.size();
		m_values.resize(len);
		resize_if_smaller(m_storage, len);
		for(size_t i = 0; i < len; i++) {
			auto v = values[i];
			resize_if_smaller(m_storage[i], v.len);
			if(v.len > 0) {
				ASSERT(v.ptr != nullptr);
				memcpy(m_storage[i].data(), v.ptr, v.len);
			}
			v.ptr = m_storage[i].data();
			m_values[i] = v;
		}
	}

	inline const std::vector<extract_value_t>& values() const { return m_values; }

	inline bool result() const { return m_result; }

	inline const std::vector<extract_offset_t>& offsets() const { return m_offsets; }

private:
	template<typename T>
	static inline void resize_if_smaller(T& v, size_t len) {
		if(v.size() < len) {
			v.resize(len);
		}
	}

	uint64_t m_evtnum = UINT64_MAX;
	bool m_result = false;
	std::vector<extract_value_t> m_values;
	std::vector<std::vector<uint8_t>> m_storage;
	std::vector<extract_offset_t> m_offsets;
};

/**
 * @brief Represents a cache value storage for comparisons in filters
 */
class sinsp_filter_compare_cache {
public:
	inline void reset() { m_evtnum = UINT64_MAX; }

	inline bool is_valid(const sinsp_evt* evt) const {
		return evt->get_num() != 0 && m_evtnum != UINT64_MAX && evt->get_num() == m_evtnum;
	}

	inline void update(const sinsp_evt* evt, bool res) {
		m_evtnum = evt->get_num();
		m_result = res;
	}

	inline bool result() const { return m_result; }

private:
	uint64_t m_evtnum = UINT64_MAX;
	bool m_result = false;
};

/**
 * @brief Represents a set of metrics and counters related to the usage
 * of cache optimizations in filters
 */
struct sinsp_filter_cache_metrics {
	inline void reset() {
		m_num_extract = 0;
		m_num_extract_cache = 0;
		m_num_compare = 0;
		m_num_compare_cache = 0;
	}

	// The number of times extract() was called
	uint64_t m_num_extract = 0;

	// The number of times extract() could use a cached value
	uint64_t m_num_extract_cache = 0;

	// The number of times compare() was called
	uint64_t m_num_compare = 0;

	// The number of times compare() could use a cached value
	uint64_t m_num_compare_cache = 0;
};

/**
 * @brief Interface for factories of filter cache objects
 */
class sinsp_filter_cache_factory {
public:
	using ast_expr_t = libsinsp::filter::ast::expr;

	/**
	 * @brief Input struct representing information about a filter AST node
	 */
	struct node_info_t {
		// For nodes representing a field extraction, the information about the field.
		// For nodes with a comparison, the information about the left-hand side field.
		// Left to null in all other cases.
		const filtercheck_field_info* m_field = nullptr;

		// For nodes with a comparison, the information about the right-hand side field.
		// Left to null in all other cases.
		const filtercheck_field_info* m_right_field = nullptr;

		// For nodes with a comparison, the comparison operator.
		// Left to CO_NONE in all other cases.
		cmpop m_compare_operator = cmpop::CO_NONE;
	};

	virtual ~sinsp_filter_cache_factory() = default;

	/**
	 * @brief Resets the state of the given factory instance
	 */
	virtual void reset() {
		// do nothing
	}

	/**
	 * @brief Given the provided AST node of a filter expression, returns a pointer
	 * to an extraction cache usable in the compiled filter derived from that node.
	 * Can return `nullptr` in case no cache is available for the node.
	 */
	virtual std::shared_ptr<sinsp_filter_extract_cache> new_extract_cache(const ast_expr_t* e,
	                                                                      node_info_t& info) {
		return nullptr;
	}

	/**
	 * @brief Given the provided AST node of a filter expression, returns a pointer
	 * to an comparison cache usable in the compiled filter derived from that node.
	 * Can return `nullptr` in case no cache is available for the node.
	 */
	virtual std::shared_ptr<sinsp_filter_compare_cache> new_compare_cache(const ast_expr_t* e,
	                                                                      node_info_t& info) {
		return nullptr;
	}

	/**
	 * @brief Given the provided AST node of a filter expression, returns a pointer
	 * to an cache metrics storage usable in the compiled filter derived from that node.
	 * Can return `nullptr` in case no metrics are available for the node.
	 */
	virtual std::shared_ptr<sinsp_filter_cache_metrics> new_metrics(const ast_expr_t* e,
	                                                                node_info_t& info) {
		return nullptr;
	}
};

/**
 * @brief An implementation of sinsp_filter_cache_factory that creates shared
 * cache objects indexed by the string representation of AST expressions
 * (obtained through libsinsp::filter::ast::as_string).
 */
class exprstr_sinsp_filter_cache_factory : public sinsp_filter_cache_factory {
public:
	virtual ~exprstr_sinsp_filter_cache_factory() = default;

	void reset() override {
		m_extract_caches.clear();
		m_compare_caches.clear();
	}

	std::shared_ptr<sinsp_filter_extract_cache> new_extract_cache(const ast_expr_t* e,
	                                                              node_info_t& info) override {
		// avoid caching fields for which it would be unsafe
		if(info.m_field && info.m_field->m_type == PT_IPNET) {
			return nullptr;
		}
		auto key = libsinsp::filter::ast::as_string(e);
		return get_or_insert_ptr(key, m_extract_caches);
	}

	std::shared_ptr<sinsp_filter_compare_cache> new_compare_cache(const ast_expr_t* e,
	                                                              node_info_t& info) override {
		// avoid caching fields for which it would be unsafe
		if(info.m_field && info.m_field->m_type == PT_IPNET) {
			return nullptr;
		}
		auto key = libsinsp::filter::ast::as_string(e);
		return get_or_insert_ptr(key, m_compare_caches);
	}

	inline const std::unordered_map<std::string, std::shared_ptr<sinsp_filter_extract_cache>>&
	extract_cache() const {
		return m_extract_caches;
	}

	inline const std::unordered_map<std::string, std::shared_ptr<sinsp_filter_compare_cache>>&
	compare_cache() const {
		return m_compare_caches;
	}

private:
	template<typename T>
	static inline std::shared_ptr<T> get_or_insert_ptr(
	        const std::string& key,
	        std::unordered_map<std::string, std::shared_ptr<T>>& map) {
		auto it = map.find(key);
		if(it == map.end()) {
			return map.emplace(key, std::make_shared<T>()).first->second;
		}
		return it->second;
	}

	std::unordered_map<std::string, std::shared_ptr<sinsp_filter_extract_cache>> m_extract_caches;
	std::unordered_map<std::string, std::shared_ptr<sinsp_filter_compare_cache>> m_compare_caches;
};

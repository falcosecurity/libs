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

#include <libsinsp/state/table_entry.h>

#include <string>
#include <unordered_map>

namespace libsinsp {
namespace state {

/**
 * @brief A group of field infos, describing all the ones available
 * in a static struct.
 */
using static_field_infos = std::unordered_map<std::string, accessor>;

template<typename>
struct member_class;

template<typename C, typename T>
struct member_class<T C::*> {
	using type = C;
};

template<typename>
struct fn_container;

template<typename Ret, typename C, typename... Args>
struct fn_container<Ret (*)(const C*, Args...)> {
	using type = C;
};

template<typename Ret, typename C, typename... Args>
struct fn_container<Ret (*)(C*, Args...)> {
	using type = C;
};

template<ss_plugin_state_type StateType, auto Fn>
borrowed_state_data read_fn(const void* obj, size_t) {
	using FnType = decltype(Fn);
	using Container = typename fn_container<FnType>::type;

	auto* c = static_cast<const Container*>(obj);
	auto&& value = Fn(c);

	using decayed_t = std::decay_t<decltype(value)>;
	return borrowed_state_data::from<StateType, decayed_t>(value);
}

template<typename Base, auto... Members>
struct nested_member;

template<typename Base, auto Member>
struct nested_member<Base, Member> {
	using container_type = typename member_class<decltype(Member)>::type;
	using leaf_type = std::decay_t<decltype(std::declval<container_type>().*Member)>;

	static decltype(auto) get(const Base* obj) { return obj->*Member; }
	static decltype(auto) get(Base* obj) { return obj->*Member; }
};

template<typename Base, auto First, auto Second, auto... Rest>
struct nested_member<Base, First, Second, Rest...> {
	using first_container = typename member_class<decltype(First)>::type;
	using leaf_type = typename nested_member<first_container, Second, Rest...>::leaf_type;

	static decltype(auto) get(const Base* obj) {
		static_assert(std::is_same<Base, first_container>::value,
		              "nested_member chain: first member does not belong to Base");

		const auto& sub = obj->*First;
		using sub_t = std::decay_t<decltype(sub)>;
		return nested_member<sub_t, Second, Rest...>::get(&sub);
	}

	static decltype(auto) get(Base* obj) {
		static_assert(std::is_same<Base, first_container>::value,
		              "nested_member chain: first member does not belong to Base");

		auto& sub = obj->*First;
		using sub_t = std::decay_t<decltype(sub)>;
		return nested_member<sub_t, Second, Rest...>::get(&sub);
	}
};

template<ss_plugin_state_type StateType, auto... Members>
borrowed_state_data read_field_typed(const void* obj, size_t) {
	static_assert(sizeof...(Members) >= 1,
	              "read_field_nested requires at least one member pointer");

	// The container is the class type of the first pointer-to-member in the chain.
	using first_member_t = std::decay_t<decltype(std::get<0>(std::tuple{Members...}))>;
	using Container = typename member_class<first_member_t>::type;

	auto* c = static_cast<const Container*>(obj);

	// Reach the final leaf (may be a reference).
	decltype(auto) value = nested_member<Container, Members...>::get(c);
	using decayed_t = std::decay_t<decltype(value)>;

	if constexpr(StateType == SS_PLUGIN_ST_TABLE && std::is_base_of_v<base_table, decayed_t>) {
		auto* tbl = const_cast<base_table*>(static_cast<const base_table*>(&value));
		return borrowed_state_data::from<SS_PLUGIN_ST_TABLE, base_table*>(tbl);
	}

	return borrowed_state_data::from<StateType, decayed_t>(value);
}

template<auto... Members>
borrowed_state_data read_field(const void* obj, size_t) {
	static_assert(sizeof...(Members) >= 1,
	              "read_field_nested requires at least one member pointer");

	// The container is the class type of the first pointer-to-member in the chain.
	using first_member_t = std::decay_t<decltype(std::get<0>(std::tuple{Members...}))>;
	using Container = typename member_class<first_member_t>::type;

	auto* c = static_cast<const Container*>(obj);

	// Reach the final leaf (may be a reference).
	decltype(auto) value = nested_member<Container, Members...>::get(c);
	using decayed_t = std::decay_t<decltype(value)>;
	constexpr ss_plugin_state_type type_id = type_id_of<decayed_t>();

	return borrowed_state_data::from<type_id, decayed_t>(value);
}

template<auto Fn>
void write_fn(void* obj, size_t, const borrowed_state_data& in_data) {
	using FnType = decltype(Fn);
	using Container = typename fn_container<FnType>::type;

	auto* c = static_cast<Container*>(obj);
	Fn(c, in_data);
}

template<typename StateType, auto... Members>
void write_field_typed(void* obj, size_t, const borrowed_state_data& in) {
	static_assert(sizeof...(Members) >= 1, "write_field requires at least one member pointer");

	using first_member_t = std::decay_t<decltype(std::get<0>(std::tuple{Members...}))>;
	using Container = typename member_class<first_member_t>::type;

	auto* c = static_cast<Container*>(obj);

	auto& value = nested_member<Container, Members...>::get(c);
	using decayed_t = std::decay_t<decltype(value)>;
	in.copy_to<type_id_of<StateType>(), decayed_t>(value);
}

template<auto... Members>
void write_field(void* obj, size_t, const borrowed_state_data& in) {
	static_assert(sizeof...(Members) >= 1, "write_field requires at least one member pointer");

	using first_member_t = std::decay_t<decltype(std::get<0>(std::tuple{Members...}))>;
	using Container = typename member_class<first_member_t>::type;

	auto* c = static_cast<Container*>(obj);

	decltype(auto) value = nested_member<Container, Members...>::get(c);
	using decayed_t = std::decay_t<decltype(value)>;
	constexpr ss_plugin_state_type type_id = type_id_of<decayed_t>();

	in.copy_to<type_id, decayed_t>(value);
}

static inline void reject_write(void*, size_t, const borrowed_state_data&) {
	throw sinsp_exception("attempt to write to read-only field");
}

};  // namespace state
};  // namespace libsinsp

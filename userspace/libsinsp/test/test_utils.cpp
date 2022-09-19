/*
Copyright (C) 2021 The Falco Authors.

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

#include "test_utils.h"

namespace test_utils {

std::string to_null_delimited(const std::vector<std::string> list)
{
	std::string res;

	for (std::string item : list) {
		res += item;
		res.push_back('\0');
	}

	return res;
}

template<typename T>
std::set<T> unordered_set_to_ordered(std::unordered_set<T> unordered_set)
{
	std::set<T> s;
	for(const auto& val : unordered_set)
	{
		s.insert(val);
	}
	return s;
}
template std::set<uint32_t> unordered_set_to_ordered(std::unordered_set<uint32_t> unordered_set);
template std::set<std::string> unordered_set_to_ordered(std::unordered_set<std::string> unordered_set);

} // namespace test_utils

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

#pragma once

#include <string>
#include <vector>
#include <set>
#include <unordered_set>

namespace test_utils {

// transform a list of strings into a single string where each element is delimited by a null (0) byte.
// the last element will also be null-terminated unless the input list is empty.
std::string to_null_delimited(std::vector<std::string> list);

// This helper is used to convert an unordered set into an ordered set.
template<typename T>
std::set<T> unordered_set_to_ordered(std::unordered_set<T> unordered_set);

} // namespace test_utils

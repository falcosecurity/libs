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

#pragma once

namespace libsinsp {
namespace filter {
	/*!
		\brief A struct containing info about a position relatively
		to the string input. For example, this can either be used
		to retrieve context information when an exception is thrown.
	*/
	struct pos_info
	{
		inline void reset()
		{
			idx = 0;
			line = 1;
			col = 1;
		}

		inline std::string as_string() const
		{
			return "index " + std::to_string(idx)
				+ ", line " + std::to_string(line)
				+ ", column " + std::to_string(col);
		}

		uint32_t idx;
		uint32_t line;
		uint32_t col;
	};
} // namespace filter {
} // namespace libsinsp {

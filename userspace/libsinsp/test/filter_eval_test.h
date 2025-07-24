// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2025 The Falco Authors.

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

#include <sinsp_with_test_input.h>

/*!
  \brief Test case for the filter_eval_test fixture.
*/
struct filter_eval_test_case {
	enum expected_filter_result : uint8_t { EXPECT_TRUE, EXPECT_FALSE, EXPECT_THROW };

	std::string name;
	std::string filter_str;
	expected_filter_result expected_result;

	std::string expected_result_to_string() const {
		switch(expected_result) {
		case EXPECT_TRUE:
			return "true";
		case EXPECT_FALSE:
			return "false";
		case EXPECT_THROW:
			return "throw";
		default:
			ASSERT(false);
			throw std::runtime_error("unexpected filter result: " +
			                         std::to_string(expected_result));
		}
	}

	friend std::ostream& operator<<(std::ostream& os, const filter_eval_test_case& tc) {
		return os << "(filter=" << tc.filter_str
		          << ", expected_result=" << tc.expected_result_to_string() << ")";
	}
};

/*!
  \brief Fixture allowing to evaluate filters on events and test the outcomes.
*/
class filter_eval_test : public testing::WithParamInterface<filter_eval_test_case>,
                         public sinsp_with_test_input {
public:
	static std::string test_case_name_gen(const testing::TestParamInfo<ParamType>& info) {
		return info.param.name;
	}
};

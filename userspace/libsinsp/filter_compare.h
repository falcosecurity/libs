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

#include <libscap/scap.h>
#include <libsinsp/tuples.h>

#include <string>
#include <unordered_set>
#include <memory>

/*
 * Operators to compare events
 */
enum cmpop: uint8_t
{
	CO_NONE = 0,
	CO_EQ = 1,
	CO_NE = 2,
	CO_LT = 3,
	CO_LE = 4,
	CO_GT = 5,
	CO_GE = 6,
	CO_CONTAINS = 7,
	CO_IN = 8,
	CO_EXISTS = 9,
	CO_ICONTAINS = 10,
	CO_STARTSWITH = 11,
	CO_GLOB = 12,
	CO_PMATCH = 13,
	CO_ENDSWITH = 14,
	CO_INTERSECTS = 15,
	CO_BCONTAINS = 16,
	CO_BSTARTSWITH = 17,
	CO_IGLOB = 18,
};

cmpop str_to_cmpop(std::string_view str);
bool cmpop_to_str(cmpop op, std::string& out);

namespace std
{
std::string to_string(cmpop);
}

bool flt_is_comparable(cmpop op, ppm_param_type t, bool is_list, std::string& err);
bool flt_compare(cmpop op, ppm_param_type type, const void* operand1, const void* operand2, uint32_t op1_len = 0, uint32_t op2_len = 0);
bool flt_compare_avg(cmpop op, ppm_param_type type, const void* operand1, const void* operand2, uint32_t op1_len, uint32_t op2_len, uint32_t cnt1, uint32_t cnt2);
bool flt_compare_ipv4net(cmpop op, uint64_t operand1, const ipv4net* operand2);
bool flt_compare_ipv6net(cmpop op, const ipv6addr *operand1, const ipv6net *operand2);

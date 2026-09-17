// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2026 The Falco Authors.

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

#include <libsinsp/sinsp.h>
#include <libsinsp/filter_compare.h>
#include <libsinsp/value_parser.h>
#include <gtest/gtest.h>

#include <cstring>
#include <optional>
#include <random>
#include <string>
#include <vector>

// A comparison shape resolved once has to answer what flt_compare answers, for every type, operator
// and value, including when flt_compare throws. Each shape is a hand-written copy of one corner of
// flt_compare, so this holds the two against each other over the whole space rather than trusting
// a reading of either.

namespace {

// A check of a given type that compares whatever it is handed, through both compare_rhs forms.
class resolved_compare_check : public sinsp_filter_check {
public:
	explicit resolved_compare_check(ppm_param_type type):
	        m_field_info{type, 0, PF_NA, "", "", ""} {}

	const filtercheck_field_info* get_field_info() const override { return &m_field_info; }

	bool compare_pointer(const void* lhs, uint32_t len) {
		return compare_rhs(m_cmp, m_field_info.m_type, lhs, len);
	}

	bool compare_vector(const void* lhs, uint32_t len) {
		std::vector<extract_value_t> values{{(uint8_t*)lhs, len}};
		return compare_rhs(m_cmp, m_field_info.m_type, values);
	}

	const uint8_t* rhs() { return filter_value_p(); }
	uint32_t rhs_len() { return filter_value_len(); }

	filtercheck_field_info m_field_info;
};

template<typename F>
std::optional<bool> answer(F&& f) {
	try {
		return f();
	} catch(const std::exception&) {
		// A refusal is an answer too: what matters is that both sides give the same one.
		return std::nullopt;
	}
}

std::string describe(const std::optional<bool>& a) {
	return a.has_value() ? (*a ? "true" : "false") : "throws";
}

struct type_case {
	ppm_param_type type;
	// Right-hand values, and left-hand ones parsed from the same strings so that equality is hit.
	std::vector<std::string> values;
	// The lengths a left-hand value is handed over with, besides its own.
	std::vector<uint32_t> extra_lens;
	// Left-hand values of their own, parsed as another type, for a type whose values come in more
	// than one shape.
	std::vector<std::string> lhs_values = {};
	ppm_param_type lhs_type = PT_NONE;
};

// Zero, both signs, and the edges of each width, where a load at the wrong width or a missing
// sign extension shows.
const std::vector<std::string> s_integers = {"0",
                                             "1",
                                             "-1",
                                             "127",
                                             "-128",
                                             "255",
                                             "65535",
                                             "-2147483648",
                                             "4294967295",
                                             "-9223372036854775808",
                                             "18446744073709551615"};

const std::vector<std::string> s_strings = {"", "a", "b", "ab", "ba", "aba", "abab", "bab"};

// Every integer and string type a constant can be parsed for. PT_SIGTYPE and PT_SYSCALLID are
// left out because none can: no filter compares one against a constant.
const std::vector<type_case> s_cases = {
        {PT_INT8, s_integers, {0, 4, 8}},
        {PT_INT16, s_integers, {0, 1, 4, 8}},
        {PT_INT32, s_integers, {0, 1, 2, 8}},
        {PT_INT64, s_integers, {0, 1, 4, 16}},
        {PT_FD, s_integers, {0, 4}},
        {PT_PID, s_integers, {0, 4}},
        {PT_ERRNO, s_integers, {0, 4}},
        {PT_UINT8, s_integers, {0, 4, 8}},
        {PT_FLAGS8, s_integers, {0, 4}},
        {PT_ENUMFLAGS8, s_integers, {0, 4}},
        {PT_UINT16, s_integers, {0, 1, 4, 8}},
        {PT_FLAGS16, s_integers, {0, 4}},
        {PT_ENUMFLAGS16, s_integers, {0, 4}},
        {PT_PORT, s_integers, {0, 1, 4}},
        {PT_UINT32, s_integers, {0, 1, 2, 8}},
        {PT_FLAGS32, s_integers, {0, 2, 8}},
        {PT_ENUMFLAGS32, s_integers, {0, 2, 8}},
        {PT_MODE, s_integers, {0, 2, 8}},
        {PT_UID, s_integers, {0, 2, 8}},
        {PT_GID, s_integers, {0, 2, 8}},
        {PT_UINT64, s_integers, {0, 1, 4, 16}},
        {PT_RELTIME, s_integers, {0, 4}},
        {PT_ABSTIME, s_integers, {0, 4}},
        {PT_BOOL, {"true", "false"}, {0, 1, 8}},
        {PT_CHARBUF, s_strings, {0}},
        {PT_FSPATH, s_strings, {0}},
        {PT_FSRELPATH, s_strings, {0}},
};

const std::vector<cmpop> s_ops =
        {CO_EQ, CO_NE, CO_LT, CO_LE, CO_GT, CO_GE, CO_STARTSWITH, CO_CONTAINS, CO_ENDSWITH};

// The parsed value at the front of a buffer longer than any type, with noise after it, so a
// length past the value's own reads something other than zeroes.
struct lhs_value {
	uint8_t buf[64];
	uint32_t len;
};

std::vector<lhs_value> parse_lhs_values(const type_case& tc, std::mt19937_64& rng) {
	std::vector<lhs_value> out;
	const auto parse_type = tc.lhs_type != PT_NONE ? tc.lhs_type : tc.type;
	for(const auto& str : tc.lhs_values.empty() ? tc.values : tc.lhs_values) {
		lhs_value v;
		for(auto& b : v.buf) {
			b = static_cast<uint8_t>(rng());
		}
		try {
			v.len = sinsp_filter_value_parser::string_to_rawval(str.c_str(),
			                                                    str.size(),
			                                                    v.buf,
			                                                    sizeof(v.buf),
			                                                    parse_type);
		} catch(const std::exception&) {
			continue;
		}
		if(tc.type == PT_CHARBUF || tc.type == PT_FSPATH || tc.type == PT_FSRELPATH) {
			v.buf[v.len] = 0;
		}
		out.push_back(v);
	}
	// And a few that no right-hand value spells, at the width of a parsed one.
	if(!out.empty() && tc.type != PT_CHARBUF && tc.type != PT_FSPATH && tc.type != PT_FSRELPATH) {
		for(int i = 0; i < 4; i++) {
			lhs_value v;
			for(auto& b : v.buf) {
				b = static_cast<uint8_t>(rng());
			}
			v.len = out[0].len;
			out.push_back(v);
		}
	}
	return out;
}

void check_against_flt_compare(const std::vector<type_case>& cases, size_t min_compared) {
	std::mt19937_64 rng(3115);
	size_t compared = 0;
	for(const auto& tc : cases) {
		const auto lhs_values = parse_lhs_values(tc, rng);
		ASSERT_FALSE(lhs_values.empty()) << "type " << tc.type;
		for(const auto op : s_ops) {
			for(const auto& rhs : tc.values) {
				resolved_compare_check chk(tc.type);
				chk.m_cmp = comparator{op};
				try {
					chk.add_filter_value(rhs.c_str(), rhs.size(), 0);
				} catch(const std::exception&) {
					// Not a value of this type, so not a filter anyone could compile.
					continue;
				}

				// The same check for every left-hand value: the shape is resolved on the first and
				// trusted afterwards, which is the part under test.
				for(const auto& lhs : lhs_values) {
					std::vector<uint32_t> lens = tc.extra_lens;
					lens.push_back(lhs.len);
					for(const auto len : lens) {
						const auto expected = answer([&] {
							return ::flt_compare(chk.m_cmp,
							                     tc.type,
							                     lhs.buf,
							                     chk.rhs(),
							                     len,
							                     chk.rhs_len());
						});
						const auto by_pointer =
						        answer([&] { return chk.compare_pointer(lhs.buf, len); });
						const auto by_vector =
						        answer([&] { return chk.compare_vector(lhs.buf, len); });
						const auto where = "type " + std::to_string(tc.type) + " op " +
						                   std::to_string(op) + " rhs '" + rhs + "' len " +
						                   std::to_string(len);
						ASSERT_EQ(describe(by_pointer), describe(expected)) << where;
						ASSERT_EQ(describe(by_vector), describe(expected)) << where;
						compared++;
					}
				}
			}
		}
	}
	// The premise: the space is not empty because every value failed to parse.
	ASSERT_GT(compared, min_compared);
}

}  // namespace

TEST(sinsp_filter_check, a_resolved_comparison_answers_what_flt_compare_answers) {
	check_against_flt_compare(s_cases, 50000);
}

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

#pragma once

// Check that the string literal `str_literal` prefixes the memory buffer `buff`.
// note: `str_literal` must be a string literal.
#define MEMCMP_LITERAL(buff, buff_len, str_literal) \
	(((buff_len) >= sizeof(str_literal) - 1) &&     \
	 (memcmp(buff, str_literal, sizeof(str_literal) - 1) == 0))

// Parse a single `uint64_t` value from `str`, skipping `skip_len` bytes first. Return a boolean
// indicating the number was successfully parsed.
static inline bool str_parse_u64(const char* str,
                                 const size_t skip_len,
                                 const int base,
                                 uint64_t* const out) {
	const char* ptr = str + skip_len;
	char* endptr;
	*out = strtoull(ptr, &endptr, base);
	return endptr > ptr;
}

static inline bool str_scan_u64(char** str,
                                const size_t skip_len,
                                const int base,
                                uint64_t* const out) {
	const char* ptr = *str + skip_len;
	char* endptr;
	const uint64_t val = (uint64_t)strtoull(ptr, &endptr, base);
	if(endptr == ptr) {
		return false;
	}
	*out = val;
	*str = endptr;
	return true;
}

static inline bool str_scan_u32(char** str,
                                const size_t skip_len,
                                const int base,
                                uint32_t* const out) {
	const char* ptr = *str + skip_len;
	char* endptr;
	const uint32_t val = (uint32_t)strtoull(ptr, &endptr, base);
	if(endptr == ptr) {
		return false;
	}
	*out = val;
	*str = endptr;
	return true;
}

static inline bool str_scan_u16(char** str,
                                const size_t skip_len,
                                const int base,
                                uint16_t* const out) {
	const char* ptr = *str + skip_len;
	char* endptr;
	const uint16_t val = (uint16_t)strtoull(ptr, &endptr, base);
	if(endptr == ptr) {
		return false;
	}
	*out = val;
	*str = endptr;
	return true;
}

// Parse up to two `uint64_t` values from `str`, skipping `skip_len` bytes first. Return the number
// of parsed values.
static inline int str_parse_two_u64(const char* str,
                                    const size_t skip_len,
                                    const int base,
                                    uint64_t* const out1,
                                    uint64_t* const out2) {
	const char* ptr = str + skip_len;
	char* endptr;

	// Parse first number.
	*out1 = strtoull(ptr, &endptr, base);
	if(endptr == ptr) {
		return 0;
	}

	// Parse second number.
	ptr = endptr;
	*out2 = strtoull(ptr, &endptr, base);
	if(endptr == ptr) {
		return 1;
	}

	return 2;
}

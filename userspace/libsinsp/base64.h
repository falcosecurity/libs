/*
 * Copyright 2024, The Falco Authors
 *
 * Originally from Istio, Copyright 2019, Istio Authors
 * https://raw.githubusercontent.com/istio/proxy/1.18.2/extensions/common/wasm/base64.h
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <string>

class Base64
{
public:
	template<class Out> static inline void encode(const char* input, uint64_t length, bool add_padding, Out& ret);

	template<class Out> static inline bool decodeWithoutPadding(std::string_view input, Out& ret);

private:
	template<class Out>
	static inline bool decodeBase(const uint8_t cur_char, uint64_t pos, Out& ret,
				      const unsigned char* const reverse_lookup_table);

	template<class Out>
	static inline bool decodeLast(const uint8_t cur_char, uint64_t pos, Out& ret,
				      const unsigned char* const reverse_lookup_table);

	template<class Out>
	static inline void encodeBase(const uint8_t cur_char, uint64_t pos, uint8_t& next_c, Out& ret,
				      const char* const char_table);

	template<class Out>
	static inline void encodeLast(uint64_t pos, uint8_t last_char, Out& ret, const char* const char_table,
				      bool add_padding);

	// clang-format off
    static inline constexpr char CHAR_TABLE[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    static inline constexpr unsigned char REVERSE_LOOKUP_TABLE[256] = {
            64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
            64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
            52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64, 64, 0,  1,  2,  3,  4,  5,  6,
            7,  8,  9,  10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
            64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
            49, 50, 51, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
            64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
            64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
            64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
            64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
            64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64};
	// clang-format on
};

template<class Out>
bool Base64::decodeBase(const uint8_t cur_char, uint64_t pos, Out& ret, const unsigned char* const reverse_lookup_table)
{
	const unsigned char c = reverse_lookup_table[static_cast<uint32_t>(cur_char)];
	if(c == 64)
	{
		// Invalid character
		return false;
	}

	switch(pos % 4)
	{
	case 0:
		ret.push_back(c << 2);
		break;
	case 1:
		ret.back() |= c >> 4;
		ret.push_back(c << 4);
		break;
	case 2:
		ret.back() |= c >> 2;
		ret.push_back(c << 6);
		break;
	case 3:
		ret.back() |= c;
		break;
	}
	return true;
}

template<class Out>
bool Base64::decodeLast(const uint8_t cur_char, uint64_t pos, Out& ret, const unsigned char* const reverse_lookup_table)
{
	const unsigned char c = reverse_lookup_table[static_cast<uint32_t>(cur_char)];
	if(c == 64)
	{
		// Invalid character
		return false;
	}

	switch(pos % 4)
	{
	case 0:
		return false;
	case 1:
		ret.back() |= c >> 4;
		return (c & 0b1111) == 0;
	case 2:
		ret.back() |= c >> 2;
		return (c & 0b11) == 0;
	case 3:
		ret.back() |= c;
		break;
	}
	return true;
}

template<class Out>
void Base64::encodeBase(const uint8_t cur_char, uint64_t pos, uint8_t& next_c, Out& ret, const char* const char_table)
{
	switch(pos % 3)
	{
	case 0:
		ret.push_back(char_table[cur_char >> 2]);
		next_c = (cur_char & 0x03) << 4;
		break;
	case 1:
		ret.push_back(char_table[next_c | (cur_char >> 4)]);
		next_c = (cur_char & 0x0f) << 2;
		break;
	case 2:
		ret.push_back(char_table[next_c | (cur_char >> 6)]);
		ret.push_back(char_table[cur_char & 0x3f]);
		next_c = 0;
		break;
	}
}

template<class Out>
void Base64::encodeLast(uint64_t pos, uint8_t last_char, Out& ret, const char* const char_table, bool add_padding)
{
	switch(pos % 3)
	{
	case 1:
		ret.push_back(char_table[last_char]);
		if(add_padding)
		{
			ret.push_back('=');
			ret.push_back('=');
		}
		break;
	case 2:
		ret.push_back(char_table[last_char]);
		if(add_padding)
		{
			ret.push_back('=');
		}
		break;
	default:
		break;
	}
}

template<class Out> void Base64::encode(const char* input, uint64_t length, bool add_padding, Out& ret)
{
	uint64_t output_length = (length + 2) / 3 * 4;
	ret.clear();
	ret.reserve(output_length);

	uint64_t pos = 0;
	uint8_t next_c = 0;

	for(uint64_t i = 0; i < length; ++i)
	{
		encodeBase(input[i], pos++, next_c, ret, CHAR_TABLE);
	}

	encodeLast(pos, next_c, ret, CHAR_TABLE, add_padding);
}

template<class Out> bool Base64::decodeWithoutPadding(std::string_view input, Out& ret)
{
	ret.clear();
	if(input.empty())
	{
		return true;
	}

	// At most last two chars can be '='.
	size_t n = input.length();
	if(input[n - 1] == '=')
	{
		n--;
		if(n > 0 && input[n - 1] == '=')
		{
			n--;
		}
	}
	// Last position before "valid" padding character.
	uint64_t last = n - 1;
	// Determine output length.
	size_t max_length = (n + 3) / 4 * 3;
	if(n % 4 == 3)
	{
		max_length -= 1;
	}
	if(n % 4 == 2)
	{
		max_length -= 2;
	}

	ret.reserve(max_length);
	for(uint64_t i = 0; i < last; ++i)
	{
		if(!decodeBase(input[i], i, ret, REVERSE_LOOKUP_TABLE))
		{
			return false;
		}
	}

	if(!decodeLast(input[last], last, ret, REVERSE_LOOKUP_TABLE))
	{
		return false;
	}

	return ret.size() == max_length;
}

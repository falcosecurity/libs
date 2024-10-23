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

#include <libsinsp/base64.h>
#include <libsinsp/sinsp_filter_transformer.h>
#include <cstring>

static void throw_unsupported_err(filter_transformer_type t) {
	throw sinsp_exception("transformer '" + std::to_string(t) + "' is not supported");
}

static void throw_type_incompatibility_err(ppm_param_type t, const std::string& trname) {
	throw sinsp_exception("field type '" + std::to_string(t) + "' is not supported by '" + trname +
	                      "' transformer");
}

bool sinsp_filter_transformer::string_transformer(std::vector<extract_value_t>& vec,
                                                  ppm_param_type t,
                                                  str_transformer_func_t f) {
	m_storage_values.resize(vec.size());
	for(std::size_t i = 0; i < vec.size(); i++) {
		storage_t& buf = m_storage_values[i];

		buf.clear();
		if(vec[i].ptr == nullptr) {
			continue;
		}

		// we don't know whether this will come as a string or a byte buf,
		// so we sanitize by skipping all terminator characters
		size_t in_len = vec[i].len;
		while(in_len > 0 && vec[i].ptr[in_len - 1] == '\0') {
			in_len--;
		}

		// each function can assume that the input size does NOT include
		// the terminator character, and should not assume that the string
		// is null-terminated
		std::string_view in{(const char*)vec[i].ptr, in_len};
		if(!f(in, buf)) {
			return false;
		}

		// we insert a null terminator in case we miss one, just to stay safe
		if(buf.size() == 0 || buf[buf.size() - 1] != '\0') {
			buf.push_back('\0');
		}

		vec[i].ptr = (uint8_t*)&buf[0];
		vec[i].len = buf.size();
	}
	return true;
}

bool sinsp_filter_transformer::transform_type(ppm_param_type& t, uint32_t& flags) const {
	bool is_list = flags & EPF_IS_LIST;
	switch(m_type) {
	case FTR_TOUPPER: {
		switch(t) {
		case PT_CHARBUF:
		case PT_FSPATH:
		case PT_FSRELPATH:
			// for TOUPPER, the transformed type is the same as the input type
			return !is_list;
		default:
			return false;
		}
	}
	case FTR_TOLOWER: {
		switch(t) {
		case PT_CHARBUF:
		case PT_FSPATH:
		case PT_FSRELPATH:
			// for TOLOWER, the transformed type is the same as the input type
			return !is_list;
		default:
			return false;
		}
	}
	case FTR_BASE64: {
		switch(t) {
		case PT_CHARBUF:
		case PT_BYTEBUF:
			// for BASE64, the transformed type is the same as the input type
			return !is_list;
		default:
			return false;
		}
	}
	case FTR_STORAGE: {
		// for STORAGE, the transformed type is the same as the input type
		return true;
	}
	case FTR_BASENAME: {
		switch(t) {
		case PT_CHARBUF:
		case PT_FSPATH:
		case PT_FSRELPATH:
			// for BASENAME, the transformed type is the same as the input type
			return !is_list;
		default:
			return false;
		}
	}
	case FTR_LEN: {
		if(is_list) {
			t = PT_UINT64;
			flags = 0;
			return true;
		}
		switch(t) {
		case PT_CHARBUF:
		case PT_BYTEBUF:
		case PT_FSPATH:
		case PT_FSRELPATH:
			t = PT_UINT64;
			return true;
		default:
			return false;
		}
	}
	default:
		throw_unsupported_err(m_type);
		return false;
	}
}

bool sinsp_filter_transformer::transform_values(std::vector<extract_value_t>& vec,
                                                ppm_param_type& t,
                                                uint32_t& flags) {
	bool is_list = flags & EPF_IS_LIST;
	ppm_param_type original_type = t;
	if(!transform_type(t, flags)) {
		throw_type_incompatibility_err(t, filter_transformer_type_str(m_type));
	}

	switch(m_type) {
	case FTR_TOUPPER: {
		return string_transformer(vec, t, [](std::string_view in, storage_t& out) -> bool {
			for(auto c : in) {
				out.push_back(toupper(c));
			}
			return true;
		});
	}
	case FTR_TOLOWER: {
		return string_transformer(vec, t, [](std::string_view in, storage_t& out) -> bool {
			for(auto c : in) {
				out.push_back(tolower(c));
			}
			return true;
		});
	}
	case FTR_BASE64: {
		return string_transformer(vec, t, [](std::string_view in, storage_t& out) -> bool {
			return Base64::decodeWithoutPadding(in, out);
		});
	}
	case FTR_STORAGE: {
		// note: for STORAGE, the transformed type is the same as the input type
		m_storage_values.resize(vec.size());
		for(std::size_t i = 0; i < vec.size(); i++) {
			storage_t& buf = m_storage_values[i];

			buf.clear();
			if(vec[i].ptr == nullptr) {
				continue;
			}

			// We reserve one extra chat for the null terminator
			buf.resize(vec[i].len + 1);
			memcpy(&(buf[0]), vec[i].ptr, vec[i].len);
			// We put the string terminator in any case
			buf[vec[i].len] = '\0';
			vec[i].ptr = &(buf[0]);
			// `vec[i].len` is the same as before
		}
		return true;
	}
	case FTR_BASENAME: {
		return string_transformer(vec, t, [](std::string_view in, storage_t& out) -> bool {
			auto last_slash_pos = in.find_last_of("/");
			std::string_view::size_type start_idx =
			        last_slash_pos == std::string_view::npos ? 0 : last_slash_pos + 1;

			for(std::string_view::size_type i = start_idx; i < in.length(); i++) {
				out.push_back(in[i]);
			}

			return true;
		});
	}
	case FTR_LEN: {
		assert((void("len() type must be PT_UINT64"), t == PT_UINT64));
		if(is_list) {
			uint64_t len = static_cast<uint64_t>(vec.size());
			auto stored_val = store_scalar(len);
			vec.clear();
			vec.push_back(stored_val);
			return true;
		}

		// not a list: could be string or buffer
		bool is_string = false;
		switch(original_type) {
		case PT_CHARBUF:
		case PT_FSPATH:
		case PT_FSRELPATH:
			is_string = true;
			break;
		case PT_BYTEBUF:
			is_string = false;
			break;
		default:
			return false;
		}

		for(std::size_t i = 0; i < vec.size(); i++) {
			uint64_t len;
			if(vec[i].ptr == nullptr) {
				vec[i] = store_scalar(0);
				continue;
			}

			if(is_string) {
				len = static_cast<uint64_t>(
				        strnlen(reinterpret_cast<const char*>(vec[i].ptr), vec[i].len));
				vec[i] = store_scalar(len);
				continue;
			}

			len = static_cast<uint64_t>(vec[i].len);
			vec[i] = store_scalar(len);
		}
		return true;
	}
	default:
		throw_unsupported_err(m_type);
		return false;
	}
}

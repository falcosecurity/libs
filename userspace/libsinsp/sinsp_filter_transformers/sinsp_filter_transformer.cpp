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

#include <libsinsp/sinsp_filter_transformers/sinsp_filter_transformer.h>

sinsp_filter_transformer::~sinsp_filter_transformer() {}

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

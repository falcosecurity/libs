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

#include <libsinsp/sinsp_filter_transformers/sinsp_filter_transformer_storage.h>

sinsp_filter_transformer_storage::sinsp_filter_transformer_storage() {
	m_type = FTR_STORAGE;
};

bool sinsp_filter_transformer_storage::transform_type(ppm_param_type& t, uint32_t& flags) const {
	return true;
}

bool sinsp_filter_transformer_storage::transform_values(std::vector<extract_value_t>& vec,
                                                        ppm_param_type& t,
                                                        uint32_t& flags) {
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

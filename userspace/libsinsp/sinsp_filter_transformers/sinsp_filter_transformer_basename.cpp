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

#include <libsinsp/sinsp_filter_transformers/sinsp_filter_transformer_basename.h>

sinsp_filter_transformer_basename::sinsp_filter_transformer_basename() {
	m_type = FTR_BASENAME;
};

bool sinsp_filter_transformer_basename::transform_type(ppm_param_type& t, uint32_t& flags) const {
	switch(t) {
	case PT_CHARBUF:
	case PT_FSPATH:
	case PT_FSRELPATH:
		// for BASENAME, the transformed type is the same as the input type
		return true;
	default:
		return false;
	}
}

bool sinsp_filter_transformer_basename::transform_values(std::vector<extract_value_t>& vec,
                                                         ppm_param_type& t,
                                                         uint32_t& flags) {
	if(!transform_type(t, flags)) {
		throw_type_incompatibility_err(t, filter_transformer_type_str(m_type));
	}

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

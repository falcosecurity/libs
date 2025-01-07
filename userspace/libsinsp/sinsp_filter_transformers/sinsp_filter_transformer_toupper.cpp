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

#include <libsinsp/sinsp_filter_transformers/sinsp_filter_transformer_toupper.h>

sinsp_filter_transformer_toupper::sinsp_filter_transformer_toupper() {
	m_type = FTR_TOUPPER;
};

bool sinsp_filter_transformer_toupper::transform_type(ppm_param_type& t, uint32_t& flags) const {
	switch(t) {
	case PT_CHARBUF:
	case PT_FSPATH:
	case PT_FSRELPATH:
		// for TOUPPER, the transformed type is the same as the input type
		return true;
	default:
		return false;
	}
}

bool sinsp_filter_transformer_toupper::transform_values(std::vector<extract_value_t>& vec,
                                                        ppm_param_type& t,
                                                        uint32_t& flags) {
	if(!transform_type(t, flags)) {
		throw_type_incompatibility_err(t, filter_transformer_type_str(m_type));
	}

	return string_transformer(vec, t, [](std::string_view in, storage_t& out) -> bool {
		for(auto c : in) {
			out.push_back(toupper(c));
		}
		return true;
	});
}

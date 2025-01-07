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

#include <libsinsp/sinsp_filter_transformers/sinsp_filter_transformer_len.h>

sinsp_filter_transformer_len::sinsp_filter_transformer_len() {
	m_type = FTR_LEN;
};

bool sinsp_filter_transformer_len::transform_type(ppm_param_type& t, uint32_t& flags) const {
	bool is_list = flags & EPF_IS_LIST;
	if(is_list) {
		t = PT_UINT64;
		flags = flags & ~EPF_IS_LIST;
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

bool sinsp_filter_transformer_len::transform_values(std::vector<extract_value_t>& vec,
                                                    ppm_param_type& t,
                                                    uint32_t& flags) {
	bool is_list = flags & EPF_IS_LIST;
	ppm_param_type original_type = t;
	if(!transform_type(t, flags)) {
		throw_type_incompatibility_err(t, filter_transformer_type_str(m_type));
	}

	assert((void("len() type must be PT_UINT64"), t == PT_UINT64));
	m_storage_values.clear();
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

	if(vec.size() == 0) {
		// should never happen since there is no way to
		// call len() with no arguments
		return false;
	}

	// we are assuming that if this is not a list then it's a single element
	assert((void("non-list elements to transform with len() must be a vector with a single "
	             "element"),
	        vec.size() == 1));
	uint64_t len;
	if(vec[0].ptr == nullptr) {
		vec[0] = store_scalar(0);
		return true;
	}

	if(is_string) {
		len = static_cast<uint64_t>(strnlen(reinterpret_cast<const char*>(vec[0].ptr), vec[0].len));
		vec[0] = store_scalar(len);
		return true;
	}

	// buffer
	len = static_cast<uint64_t>(vec[0].len);
	vec[0] = store_scalar(len);
	return true;
}

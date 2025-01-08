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

#include <libsinsp/sinsp_filter_transformers/sinsp_filter_transformer.h>
#include <libsinsp/sinsp_filter_transformers/sinsp_filter_transformer_base64.h>
#include <libsinsp/sinsp_filter_transformers/sinsp_filter_transformer_basename.h>
#include <libsinsp/sinsp_filter_transformers/sinsp_filter_transformer_len.h>
#include <libsinsp/sinsp_filter_transformers/sinsp_filter_transformer_storage.h>
#include <libsinsp/sinsp_filter_transformers/sinsp_filter_transformer_tolower.h>
#include <libsinsp/sinsp_filter_transformers/sinsp_filter_transformer_toupper.h>

namespace sinsp_filter_transformer_factory {
inline std::unique_ptr<sinsp_filter_transformer> create_transformer(
        filter_transformer_type trtype) {
	switch(trtype) {
	case FTR_TOUPPER: {
		return std::make_unique<sinsp_filter_transformer_toupper>();
	}
	case FTR_TOLOWER: {
		return std::make_unique<sinsp_filter_transformer_tolower>();
	}
	case FTR_BASE64: {
		return std::make_unique<sinsp_filter_transformer_base64>();
	}
	case FTR_STORAGE: {
		return std::make_unique<sinsp_filter_transformer_storage>();
	}
	case FTR_BASENAME: {
		return std::make_unique<sinsp_filter_transformer_basename>();
	}
	case FTR_LEN: {
		return std::make_unique<sinsp_filter_transformer_len>();
	}
	default:
		throw sinsp_exception("transformer '" + std::to_string(trtype) + "' is not supported");
		return nullptr;
	}
}
};  // namespace sinsp_filter_transformer_factory

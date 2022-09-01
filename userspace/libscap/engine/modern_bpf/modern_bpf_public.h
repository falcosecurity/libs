/*
Copyright (C) 2022 The Falco Authors.
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

#include <stdint.h>

#define MODERN_BPF_ENGINE "modern_bpf"
#define MODERN_BPF_ENGINE_LEN 11

#ifdef __cplusplus
extern "C"
{
#endif

	struct scap_modern_bpf_engine_params
	{
		uint64_t buffer_num_pages; ///< Number of pages of a single per CPU buffer. The overall buffer dimension is: `buffer_num_pages * page_dim`.
	};

#ifdef __cplusplus
};
#endif

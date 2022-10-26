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

#define BPF_ENGINE "bpf"

#ifdef __cplusplus
extern "C"
{
#endif

	struct scap_bpf_engine_params
	{
		unsigned long buffer_bytes_dim; ///< Dimension of a single per-CPU buffer in bytes. Please note: this buffer will be mapped twice in the process virtual memory, so pay attention to its size.
		const char* bpf_probe;	    ///<  The path to the BPF probe object file.
	};

#ifdef __cplusplus
};
#endif

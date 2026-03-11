// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.
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
#define DEFAULT_CPU_FOR_EACH_BUFFER 1

#ifdef __cplusplus
extern "C" {
#endif

struct scap_modern_bpf_engine_params {
	uint16_t cpus_for_each_buffer;  ///< [EXPERIMENTAL] We will allocate a ring buffer every
	                                ///< `cpus_for_each_buffer` CPUs. `0` is a special value and
	                                ///< means a single ring buffer shared between all the CPUs.
	bool allocate_online_only;  ///< [EXPERIMENTAL] Allocate ring buffers only for online CPUs. The
	                            ///< number of ring buffers allocated changes according to the
	                            ///< `cpus_for_each_buffer` param. Please note: this buffer will be
	                            ///< mapped twice both kernel and userspace-side, so pay attention
	                            ///< to its size.
	unsigned long
	        buffer_bytes_dim;  ///< Dimension of a ring buffer in bytes. The number of ring buffers
	                           ///< allocated changes according to the `cpus_for_each_buffer` param.
	                           ///< Please note: this buffer will be mapped twice both kernel and
	                           ///< userspace-side, so pay attention to its size.
};

extern const struct scap_linux_vtable scap_modern_bpf_linux_vtable;

#ifdef __cplusplus
};
#endif

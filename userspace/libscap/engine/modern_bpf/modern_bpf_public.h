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
#define DEFAULT_BUFFERS_NUM 1

#ifdef __cplusplus
extern "C" {
#endif

struct scap_modern_bpf_engine_params {
	double buffers_num;  ///< [EXPERIMENTAL] Determines the number
	                     ///< of allocated ring buffers:
	                     ///< - if buffers_num > 1, it is the number of requested ring buffers
	                     ///< - if buffers_num > 0 && buffers_num <= 1, 1 / buffers_num is the
	                     ///<   number of CPUs to which we want to associate a ring buffer.
	                     ///< - if buffers_num == 0, it means that 1 ring buffer is shared among all
	                     ///<   available CPUs.
	bool allocate_online_only;  ///< [EXPERIMENTAL] Allocate ring buffers only for online CPUs. The
	                            ///< number of ring buffers allocated changes according to the
	                            ///< `buffers_num` param. This parameter is taken into account only
	                            ///< if buffers_num >= 0 && buffers_num <= 1. Please note: this
	                            ///< buffer will be mapped twice both kernel and userspace-side, so
	                            ///< pay attention to its size.
	unsigned long buffer_bytes_dim;  ///< Dimension of a ring buffer in bytes. The number of ring
	                                 ///< buffers allocated changes according to the `buffers_num`
	                                 ///< param. Please note: this buffer will be mapped twice both
	                                 ///< kernel and userspace-side, so pay attention to its size.
};

#ifdef __cplusplus
};
#endif

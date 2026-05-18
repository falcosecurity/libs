// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2026 The Falco Authors.

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

/*

This engine lets you process a scap file using a memory buffer. Buffers
must be a sequence of pcapng blocks as defined at
https://github.com/IETF-OPSAWG-WG/draft-ietf-opsawg-pcap, including the
block type, block total length, block body, and block total length
(again). When sinsp::next is called, the inspector will process each
block, after which the buffer can be initialized with the next sequence
of blocks.

*/

#pragma once

#include <stdint.h>
#include <libscap/scap_procs.h>

#define RAW_BLOCK_ENGINE "raw_block"

#ifdef __cplusplus
extern "C" {
#endif

struct scap_platform;

struct scap_raw_block_engine_params {
	uint8_t** buffer_ptr;       ///< Pointer to the buffer pointer (double indirection for growable
	                            ///< buffers).
	uint64_t* buffer_size_ptr;  ///< Pointer to the current buffer data size.

	struct scap_platform* platform;
};

struct scap_platform* scap_raw_block_alloc_platform(scap_proc_callbacks callbacks);

#ifdef __cplusplus
};
#endif

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
must be a sequence of whole pcapng blocks as defined at
https://github.com/IETF-OPSAWG-WG/draft-ietf-opsawg-pcap,
including the block type, block total length, block body, and block
total length (again). The buffer must always end on a block boundary; a
trailing partial block causes sinsp::next to return SCAP_FAILURE.

Two modes of processing are supported:
- Whole-file mode, where the buffer contains the entire file, including
  the section header block, any metadata blocks, and all event blocks.
  This is an in-memory equivalent to the savefile engine.
- Incremental mode, where the buffer is fed a subset of blocks in a
  capture session. The first buffer must contain the section header
  block, any metadata blocks, and zero or more event blocks. The buffer
  contents are processed by calling \ref sinsp::next until it returns
  \ref SCAP_EOF, which signals that the current buffer has been
  consumed. Additional blocks can besupplied in one of two ways:
  - Append: extend the buffer in place with the next blocks and grow
    *buffer_size_ptr. The reader continues from where it left off, so no
    reset is needed. (buffer_ptr is a double pointer so the buffer may
    be reallocated as it grows.)
  - Replace: overwrite the buffer with the next sequence of blocks and
    rewind the reader to the start of the new contents by calling
    sinsp::fseek(0). This lets the buffer be reused rather than grown.

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

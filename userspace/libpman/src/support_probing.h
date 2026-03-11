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

#pragma once

#include <driver/feature_gates.h>

#ifdef BPF_ITERATOR_SUPPORT

#include <bpf_probe.skel.h>

// Main function for support probing. Use this to probe if a specific BPF iterator program can be
// safely loaded on the current machine. Return 0 if the current machine supports the program, a
// negative number otherwise.
int iter_support_probing__probe(const char *prog_name);

// The following declarations are here just to avoid creating a separate header file. They are
// called by `iter_support_probing__probe()`. Don't use them directly.

// Context created while probing for support of a single BPF iterator program.
struct iter_support_probing_ctx {
	// Instance of the probe specifically created for a single support probing.
	struct bpf_probe *probe;
	// Store the fd of the inner map used to configure the ringbuf array before loading it.
	int32_t inner_ringbuf_map_fd;
};

int iter_support_probing__prepare_ringbuf_array_before_loading(
        struct iter_support_probing_ctx *ctx);
int iter_support_probing__prepare_maps_before_loading(struct iter_support_probing_ctx *ctx);

#endif  // BPF_ITERATOR_SUPPORT

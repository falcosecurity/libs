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

#if defined(__cplusplus)
#error "scap_stdatomic.h is for C only; use <atomic> from C++"
#endif

#if defined(_MSC_VER)
/*
 * MSVC's C runtime does not enable C11 atomics in all builds (vcruntime_c11_stdatomic.h
 * errors with "C atomic support is not enabled"). Provide a minimal compatibility
 * layer using MSVC intrinsics for the 64-bit operations used by libscap.
 */
#include <stdint.h>
#include <intrin.h>

typedef uint64_t atomic_uint_fast64_t;

static inline uint64_t scap_atomic_load_64(volatile atomic_uint_fast64_t *ptr) {
	return (uint64_t)_InterlockedOr64((volatile __int64 *)ptr, 0);
}

static inline uint64_t scap_atomic_fetch_add_64(volatile atomic_uint_fast64_t *ptr, uint64_t val) {
	return (uint64_t)_InterlockedExchangeAdd64((volatile __int64 *)ptr, (__int64)val);
}

#define atomic_load(ptr) scap_atomic_load_64(ptr)
#define atomic_fetch_add(ptr, val) scap_atomic_fetch_add_64(ptr, val)

#else
#include <stdatomic.h>
#endif

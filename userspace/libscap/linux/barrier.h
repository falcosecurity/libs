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

// This is taken from kernel headers `/include/linux/compiler.h`
// Used by libpman and scap_bpf engine

#define READ_ONCE(x) (*(volatile typeof(x) *)&x)
#define WRITE_ONCE(x, v) (*(volatile typeof(x) *)&x) = (v)

#define barrier() asm volatile("" ::: "memory")

#if defined(__x86_64__)

#define smp_mb() asm volatile("lock; addl $0,-132(%%rsp)" ::: "memory", "cc")

#define smp_store_release(p, v) \
	do {                        \
		barrier();              \
		WRITE_ONCE(*p, v);      \
	} while(0)

#define smp_load_acquire(p)              \
	({                                   \
		typeof(*p) ___p = READ_ONCE(*p); \
		barrier();                       \
		___p;                            \
	})

#elif defined(__aarch64__)

#define smp_mb() asm volatile("dmb ish" ::: "memory")

#endif

#ifndef smp_mb
#define smp_mb() __sync_synchronize()
#endif

#ifndef smp_store_release
#define smp_store_release(p, v) \
	do {                        \
		smp_mb();               \
		WRITE_ONCE(*p, v);      \
	} while(0)
#endif

#ifndef smp_load_acquire
#define smp_load_acquire(p)              \
	({                                   \
		typeof(*p) ___p = READ_ONCE(*p); \
		smp_mb();                        \
		___p;                            \
	})
#endif

// This is defined by us
#if defined(__x86_64__)
#define mem_barrier() barrier()
#else
#define mem_barrier() smp_mb()
#endif

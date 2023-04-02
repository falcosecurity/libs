/* We need this header to keep track of all struct/field/enum changes between kernel versions */

#ifndef __STRUCT_FLAVORS_H__
#define __STRUCT_FLAVORS_H__

#include "vmlinux.h"

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)
#endif

struct mm_struct___v6_2
{
	struct percpu_counter rss_stat[NR_MM_COUNTERS];
};

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif

/* We don't need relocation on these structs, they are internally defined by us as a fallback!
 * Use the prefix `modern_bpf__` before the real name of the struct we want to replace.
 */

/* We use this as a fallback for kernels where `struct __kernel_timespec` is not defined. */
struct modern_bpf__kernel_timespec
{
	long int tv_sec;
	long int tv_nsec;
};

/* We use this as a fallback for kernels where `struct __kernel_timex_timeval` is not defined. */
struct modern_bpf__kernel_timex_timeval
{
	long long int tv_sec;
	long long int tv_usec;
};

#endif /* __STRUCT_FLAVORS_H__ */

/*

Copyright (C) 2023 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/

#ifdef __KERNEL__
#include <asm/unistd.h>
#else
/*
 * In userspace, we always need to compile the full syscall table,
 * faking full support; this allows userspace code to be
 * able to manage all syscalls->events mappings,
 * even if the driver won't be able to send all syscalls.
 */
#if defined(__GNUC__)
#if defined(__x86_64__) || defined(__EMSCRIPTEN__)
#include "syscall_compat_x86_64.h"
#elif defined(__aarch64__)
#include "syscall_compat_aarch64.h"
#elif defined(__s390x__)
#include "syscall_compat_s390x.h"
#endif /* __x86_64__ */
#elif defined(_MSC_VER) || defined(__EMSCRIPTEN__)
// these are Linux syscall numbers and obviously meaningless for Windows/macOS
// but we need *some* definition so that we have a mapping for scap_ppm_sc.c
#include "syscall_compat_x86_64.h"
#endif /* __GNUC__ */
#endif /* __KERNEL__ */

#include "syscall_table.c"

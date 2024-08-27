#pragma once

#if defined(__x86_64__) || defined(__EMSCRIPTEN__)
#include "syscall_compat_x86_64.h"
#elif defined(__aarch64__)
#include "syscall_compat_aarch64.h"
#elif defined(__s390x__)
#include "syscall_compat_s390x.h"
#elif defined(__powerpc__)
#include "syscall_compat_ppc64le.h"
#elif defined(__riscv)
#include "syscall_compat_riscv64.h"
#elif defined(__loongarch__)
#include "syscall_compat_loongarch64.h"
#endif /* __x86_64__ */

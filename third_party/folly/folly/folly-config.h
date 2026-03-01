/*
 * Minimal config for vendored Folly (ConcurrentHashMap and deps).
 * Full Folly would generate this via CMake; here we hardcode Linux values.
 */
#pragma once

#ifdef __APPLE__
#include <TargetConditionals.h>
#endif

#if !defined(FOLLY_MOBILE)
#if defined(__ANDROID__) || (defined(__APPLE__) && \
                             (TARGET_IPHONE_SIMULATOR || TARGET_OS_SIMULATOR || TARGET_OS_IPHONE))
#define FOLLY_MOBILE 1
#else
#define FOLLY_MOBILE 0
#endif
#endif

#define FOLLY_HAVE_PTHREAD 1
#define FOLLY_HAVE_PTHREAD_ATFORK 1

/* We do NOT have gflags or glog as system libraries */
/* #undef FOLLY_HAVE_LIBGFLAGS */
/* #undef FOLLY_HAVE_LIBGLOG */
/* #undef FOLLY_USE_JEMALLOC */

#if __has_include(<features.h>)
#include <features.h>
#endif

#define FOLLY_HAVE_ACCEPT4 1
#define FOLLY_HAVE_GETRANDOM 1
#define FOLLY_HAVE_PREADV 1
#define FOLLY_HAVE_PWRITEV 1
#define FOLLY_HAVE_CLOCK_GETTIME 1
#define FOLLY_HAVE_PIPE2 1

#define FOLLY_HAVE_IFUNC 1
#define FOLLY_HAVE_UNALIGNED_ACCESS 1
#define FOLLY_HAVE_VLA 1
/* macOS ld64 does not resolve undefined weak symbols to zero; use pointer stubs instead */
#if defined(__APPLE__)
#define FOLLY_HAVE_WEAK_SYMBOLS 0
#else
#define FOLLY_HAVE_WEAK_SYMBOLS 1
#endif
#define FOLLY_HAVE_LINUX_VDSO 1
#define FOLLY_HAVE_MALLOC_USABLE_SIZE 1
#define FOLLY_HAVE_WCHAR_SUPPORT 1
#define HAVE_VSNPRINTF_ERRORS 1

/* #undef FOLLY_HAVE_LIBUNWIND */
#define FOLLY_HAVE_DWARF 0
#define FOLLY_HAVE_ELF 1
#define FOLLY_HAVE_SWAPCONTEXT 1
#define FOLLY_HAVE_BACKTRACE 1
/* #undef FOLLY_USE_SYMBOLIZER */
#define FOLLY_DEMANGLE_MAX_SYMBOL_SIZE 1024

#define FOLLY_HAVE_SHADOW_LOCAL_WARNINGS 1

#define FOLLY_HAVE_LIBLZ4 0
#define FOLLY_HAVE_LIBLZMA 0
#define FOLLY_HAVE_LIBSNAPPY 0
#define FOLLY_HAVE_LIBZ 0
#define FOLLY_HAVE_LIBZSTD 0
#define FOLLY_HAVE_LIBBZ2 0

#define FOLLY_LIBRARY_SANITIZE_ADDRESS 0

/* #undef FOLLY_SUPPORT_SHARED_LIBRARY */
#define FOLLY_HAVE_LIBRT 1

#define FOLLY_HAVE_VSOCK 0

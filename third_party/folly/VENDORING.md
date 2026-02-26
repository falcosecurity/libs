# Vendored Folly: ConcurrentHashMap

This directory contains a minimal subset of [Facebook Folly](https://github.com/facebook/folly)
(`v2026.02.23.00`) vendored to provide `folly::ConcurrentHashMap` and its transitive dependencies.

Licensed under the Apache License, Version 2.0 (see `NOTICES` in the repository root).

## Why vendor?

Installing the full Folly library (and its many dependencies) in CI proved difficult across
different platforms. Vendoring the minimal subset needed for `ConcurrentHashMap` eliminates
external dependency management while keeping the code close to upstream.

## What is included

The vendored subset builds a static library called **`folly_minimal`** (see `CMakeLists.txt`).
It includes:

- `folly::ConcurrentHashMap` and its internal detail headers
- Hazard pointer subsystem (`Hazptr`, `HazptrDomain`, `HazptrHolder`, `HazptrObj`, etc.)
- `SharedMutex`, `ParkingLot`, `AsymmetricThreadFence`
- Thread-local storage (`ThreadLocal`, `ThreadLocalDetail`, `SingletonThreadLocal`)
- `Futex`, `AtFork`, `CacheLocality`, `ScopeGuard`
- Supporting utilities: `Demangle`, `SafeAssert`, `ToAscii`, `CString`, `Exception`,
  `ExceptionString`, `Malloc`, `ReentrantAllocator`, `F14Table`, `ThreadId`, `SysMembarrier`,
  `StaticSingletonManager`, `UniqueInstance`

### Source files compiled (26 `.cpp` files)

| File | Purpose |
|------|---------|
| `folly/concurrency/CacheLocality.cpp` | CPU/cache topology detection |
| `folly/container/detail/F14Table.cpp` | F14 hash table link-check symbol |
| `folly/Demangle.cpp` | Symbol demangling |
| `folly/detail/Futex.cpp` | Linux futex wrapper |
| `folly/detail/StaticSingletonManager.cpp` | Singleton management |
| `folly/detail/thread_local_globals.cpp` | Thread dying detection |
| `folly/detail/ThreadLocalDetail.cpp` | ThreadLocal internals |
| `folly/detail/UniqueInstance.cpp` | Unique instance enforcement |
| `folly/ExceptionString.cpp` | Exception-to-string formatting |
| `folly/lang/CString.cpp` | `strlcpy` / `strlcat` |
| `folly/lang/Exception.cpp` | Exception utilities (`current_exception`) |
| `folly/lang/SafeAssert.cpp` | Safe assertion handlers |
| `folly/lang/ToAscii.cpp` | Integer-to-ASCII tables |
| `folly/memory/Malloc.cpp` | Allocator detection (jemalloc/tcmalloc) |
| `folly/memory/ReentrantAllocator.cpp` | Re-entrant allocator |
| `folly/portability/SysMembarrier.cpp` | `membarrier()` portability |
| `folly/ScopeGuard.cpp` | ScopeGuard termination handler |
| `folly/SharedMutex.cpp` | Read-write lock implementation |
| `folly/SingletonThreadLocal.cpp` | SingletonThreadLocal tracking |
| `folly/synchronization/AsymmetricThreadFence.cpp` | Asymmetric fence |
| `folly/synchronization/Hazptr.cpp` | Hazard pointer executor |
| `folly/synchronization/HazptrDomain.cpp` | Hazard pointer domain |
| `folly/synchronization/ParkingLot.cpp` | Thread parking primitives |
| `folly/synchronization/SanitizeThread.cpp` | Sanitizer thread hooks |
| `folly/system/AtFork.cpp` | Fork handlers |
| `folly/system/ThreadId.cpp` | Thread ID utilities |

## External dependencies

| Dependency | How handled |
|---|---|
| **glog** | Bundled via `cmake/modules/glog.cmake` (FetchContent, v0.7.1). Linked PRIVATE to `folly_minimal`. Stub headers (`folly/portability/GLog.h`, `glog/logging.h` redirect) remain in tree for compatibility. |
| **gflags** | Not needed. `folly/portability/GFlags.h` (from upstream) provides fallback macros when `FOLLY_HAVE_LIBGFLAGS` is unset. Bundled glog is built with `WITH_GFLAGS OFF`. |
| **Boost.Preprocessor** | Replaced with hand-rolled C++17-compatible macros in `folly/functional/Invoke.h`. |
| **double-conversion** | Bundled via `cmake/modules/double-conversion.cmake` (FetchContent, v3.4.0). Linked PUBLIC to `folly_minimal` because `folly/Conv.h` (a public header) includes it. `folly/Exception.h` is patched so that it does not include `Conv.h`; other code still uses `Conv.h`. |
| **fmt** | Bundled as a build dependency via `cmake/modules/fmt.cmake` (ExternalProject, version 10.2.1). |
| **jemalloc / tcmalloc** | Not required. Weak symbols in `folly/memory/detail/MallocImpl.h` resolve to `nullptr` at link time when neither allocator is present. `folly/memory/Malloc.cpp` detects this at runtime. |

## Files modified from upstream

### `folly/folly-config.h` (new file, replaces CMake-generated config)

Upstream Folly generates this header via CMake configure checks. We provide a hand-written
version with hardcoded values for Linux:

- `FOLLY_HAVE_PTHREAD`, `FOLLY_HAVE_PTHREAD_ATFORK` = 1
- `FOLLY_HAVE_WEAK_SYMBOLS` = 1 (enables weak-symbol jemalloc detection)
- `FOLLY_HAVE_LIBGFLAGS`, `FOLLY_HAVE_LIBGLOG`, `FOLLY_USE_JEMALLOC` = undefined
- `FOLLY_HAVE_ELF` = 1, `FOLLY_HAVE_DWARF` = 0
- Various Linux syscall/feature flags enabled (`ACCEPT4`, `GETRANDOM`, `PIPE2`, etc.)
- Compression libraries (`LZ4`, `LZMA`, `SNAPPY`, `ZLIB`, `ZSTD`, `BZ2`) = 0

### `folly/portability/GLog.h` (new file, glog stub)

Provides stub implementations for glog macros used throughout Folly:

- `DCHECK(cond)`, `DCHECK_EQ/NE/GE/GT/LE/LT(a, b)` -- assert-based in debug, no-op in release
- `CHECK(cond)`, `CHECK_EQ/NE/GE/GT/LE/LT(a, b)` -- same as DCHECK variants
- `PCHECK(cond)` -- same as DCHECK
- `LOG(severity)` -- no-op stream sink
- All macros support the `<< "message"` streaming syntax via `DCheckStream`/`LogStream` types

### `glog/logging.h` (new file, redirect header)

A one-line redirect so that `#include <glog/logging.h>` resolves to our stub when the real glog is not in use; when glog is bundled, the build supplies the real glog headers.

### `folly/Exception.h` (modified)

- **Removed** `#include <folly/Conv.h>` and `#include <folly/FBString.h>` so that this header does not pull in `double-conversion`; other vendored code and consumers still use `folly/Conv.h` and get `double-conversion` via the build.
- **Added** `#include <folly/lang/Exception.h>` -- provides `throw_exception` and `FOLLY_SAFE_PCHECK` definitions needed by other vendored files.
- **Changed** `makeSystemErrorExplicit(int err, Args&&... args)` to format the error message using `std::ostringstream` with a C++17 fold expression instead of `folly::to<fbstring>(...)`.

### `folly/functional/Invoke.h` (modified)

- **Removed** `#include <boost/preprocessor/control/expr_iif.hpp>` and related Boost.Preprocessor
  headers.
- **Replaced** `FOLLY_DETAIL_CREATE_FREE_INVOKE_TRAITS_USING` macro body with a `__VA_OPT__`
  implementation that supports 0 or 1 namespace argument (sufficient for all usage in the vendored
  subset). Requires C++20 `__VA_OPT__` support (GCC 8+, Clang 12+).

### `folly/Demangle.cpp` (modified)

- **Guarded** libiberty-specific code with `#ifdef DMGL_PARAMS`. `DMGL_PARAMS` is defined only by libiberty’s `<demangle.h>`. When glog is included, its internal `demangle.h` can be found first; that header does not define `DMGL_PARAMS`, so we skip the libiberty path and use the fallback demangler instead of failing to compile.

### `folly/hash/HsiehHash.h` (modified)

- **Renamed** internal macro `get16bits` to `folly_get16bits` to avoid a redefinition warning when uthash is also included. Both macros implement Paul Hsieh’s 16-bit load but differently: uthash uses a direct `uint16_t*` cast while Folly uses `folly::loadUnaligned<uint16_t>` (safe `memcpy`-based unaligned load). Renaming avoids both the warning and any subtle semantic mismatch.

## CMake integration

### `third_party/folly/CMakeLists.txt` (new file)

Defines the `folly_minimal` static library target:

- Compiles the 26 `.cpp` files listed above
- `PUBLIC` include directory: `third_party/folly/` (so consumers see `<folly/...>` headers)
- `PUBLIC` compile feature: `cxx_std_17`
- `PRIVATE` dependency on `fmt` (include dir + static lib + build dependency)
- `PUBLIC` dependency on `double-conversion` (required by public header `folly/Conv.h`); `double-conversion` and `glog` are made available by `cmake/modules/libsinsp.cmake` before this subdirectory
- `PRIVATE` dependency on `glog::glog`
- `PUBLIC` link: `Threads::Threads` (via `find_package(Threads)`), `${CMAKE_DL_LIBS}`

### `cmake/modules/double-conversion.cmake` (new file)

Provides `double-conversion` via `find_package` when `USE_BUNDLED_DOUBLE_CONVERSION` is OFF, or via FetchContent (v3.4.0) when bundled. Used by `folly_minimal` (included from `libsinsp.cmake` before the folly subdirectory).

### `cmake/modules/glog.cmake` (new file)

Provides `glog::glog` via `find_package` when `USE_BUNDLED_GLOG` is OFF, or via FetchContent (v0.7.1) when bundled; disables testing, gflags, gtest, and unwind. Used by `folly_minimal` (included from `libsinsp.cmake` before the folly subdirectory).

### `cmake/modules/fmt.cmake` (new file)

Provides `fmt` 10.2.1 as a bundled `ExternalProject`. Exports `FMT_INCLUDE_DIR` and `FMT_LIB` variables consumed by the `folly_minimal` CMakeLists.

### `cmake/modules/libsinsp.cmake` (modified)

Before the `jsoncpp` include (and only when not EMSCRIPTEN), includes folly’s dependencies and adds the folly subdirectory:

```cmake
include(tbb)
include(fmt)
include(double-conversion)
include(glog)
add_subdirectory(${LIBS_DIR}/third_party/folly ${CMAKE_BINARY_DIR}/folly_minimal)
```

### `userspace/libsinsp/CMakeLists.txt` (modified)

In the non-Emscripten block:

```cmake
target_link_libraries(sinsp PUBLIC folly_minimal)
target_compile_definitions(sinsp PUBLIC LIBSINSP_USE_FOLLY)
```

## Updating

To update the vendored code:

1. Clone/download the desired Folly release tag
2. Copy updated headers and `.cpp` files into `third_party/folly/folly/`
3. Re-apply the patches documented above (`folly-config.h`, `GLog.h`, `Exception.h`, `Invoke.h`, `Demangle.cpp`, `HsiehHash.h`)
4. Build `folly_minimal` and resolve any new missing headers or linker errors
5. Update the version reference in `NOTICES`

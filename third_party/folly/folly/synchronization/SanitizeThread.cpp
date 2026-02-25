/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <folly/Portability.h>
#include <folly/synchronization/SanitizeThread.h>

// ThreadSanitizer runtime provides these when linking with -fsanitize=thread.
extern "C" void AnnotateRWLockCreate(char const* f, int l, void const volatile* addr);
extern "C" void AnnotateRWLockCreateStatic(char const* f, int l, void const volatile* addr);
extern "C" void AnnotateRWLockDestroy(char const* f, int l, void const volatile* addr);
extern "C" void AnnotateRWLockAcquired(char const* f, int l, void const volatile* addr, long w);
extern "C" void AnnotateRWLockReleased(char const* f, int l, void const volatile* addr, long w);
extern "C" void AnnotateBenignRaceSized(char const* f,
                                        int l,
                                        void const volatile* addr,
                                        long size,
                                        char const* desc);
extern "C" void AnnotateIgnoreReadsBegin(char const* f, int l);
extern "C" void AnnotateIgnoreReadsEnd(char const* f, int l);
extern "C" void AnnotateIgnoreWritesBegin(char const* f, int l);
extern "C" void AnnotateIgnoreWritesEnd(char const* f, int l);
extern "C" void AnnotateIgnoreSyncBegin(char const* f, int l);
extern "C" void AnnotateIgnoreSyncEnd(char const* f, int l);

namespace folly {
namespace detail {

#if FOLLY_SANITIZE_THREAD
FOLLY_STORAGE_CONSTEXPR annotate_rwlock_cd_t* const annotate_rwlock_create_v =
        &AnnotateRWLockCreate;
FOLLY_STORAGE_CONSTEXPR annotate_rwlock_cd_t* const annotate_rwlock_create_static_v =
        &AnnotateRWLockCreateStatic;
FOLLY_STORAGE_CONSTEXPR annotate_rwlock_cd_t* const annotate_rwlock_destroy_v =
        &AnnotateRWLockDestroy;
FOLLY_STORAGE_CONSTEXPR annotate_rwlock_ar_t* const annotate_rwlock_acquired_v =
        &AnnotateRWLockAcquired;
FOLLY_STORAGE_CONSTEXPR annotate_rwlock_ar_t* const annotate_rwlock_released_v =
        &AnnotateRWLockReleased;
FOLLY_STORAGE_CONSTEXPR annotate_benign_race_sized_t* const annotate_benign_race_sized_v =
        &AnnotateBenignRaceSized;
FOLLY_STORAGE_CONSTEXPR annotate_ignore_t* const annotate_ignore_reads_begin_v =
        &AnnotateIgnoreReadsBegin;
FOLLY_STORAGE_CONSTEXPR annotate_ignore_t* const annotate_ignore_reads_end_v =
        &AnnotateIgnoreReadsEnd;
FOLLY_STORAGE_CONSTEXPR annotate_ignore_t* const annotate_ignore_writes_begin_v =
        &AnnotateIgnoreWritesBegin;
FOLLY_STORAGE_CONSTEXPR annotate_ignore_t* const annotate_ignore_writes_end_v =
        &AnnotateIgnoreWritesEnd;
FOLLY_STORAGE_CONSTEXPR annotate_ignore_t* const annotate_ignore_sync_begin_v =
        &AnnotateIgnoreSyncBegin;
FOLLY_STORAGE_CONSTEXPR annotate_ignore_t* const annotate_ignore_sync_end_v =
        &AnnotateIgnoreSyncEnd;
#else
FOLLY_STORAGE_CONSTEXPR annotate_rwlock_cd_t* const annotate_rwlock_create_v = nullptr;
FOLLY_STORAGE_CONSTEXPR annotate_rwlock_cd_t* const annotate_rwlock_create_static_v = nullptr;
FOLLY_STORAGE_CONSTEXPR annotate_rwlock_cd_t* const annotate_rwlock_destroy_v = nullptr;
FOLLY_STORAGE_CONSTEXPR annotate_rwlock_ar_t* const annotate_rwlock_acquired_v = nullptr;
FOLLY_STORAGE_CONSTEXPR annotate_rwlock_ar_t* const annotate_rwlock_released_v = nullptr;
FOLLY_STORAGE_CONSTEXPR annotate_benign_race_sized_t* const annotate_benign_race_sized_v = nullptr;
FOLLY_STORAGE_CONSTEXPR annotate_ignore_t* const annotate_ignore_reads_begin_v = nullptr;
FOLLY_STORAGE_CONSTEXPR annotate_ignore_t* const annotate_ignore_reads_end_v = nullptr;
FOLLY_STORAGE_CONSTEXPR annotate_ignore_t* const annotate_ignore_writes_begin_v = nullptr;
FOLLY_STORAGE_CONSTEXPR annotate_ignore_t* const annotate_ignore_writes_end_v = nullptr;
FOLLY_STORAGE_CONSTEXPR annotate_ignore_t* const annotate_ignore_sync_begin_v = nullptr;
FOLLY_STORAGE_CONSTEXPR annotate_ignore_t* const annotate_ignore_sync_end_v = nullptr;
#endif

}  // namespace detail
}  // namespace folly

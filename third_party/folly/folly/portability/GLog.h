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

#pragma once

#include <cassert>

// Stub for glog when vendoring Folly without a glog dependency.
// DCHECK* expand to no-op in NDEBUG, otherwise to assert-style checks.
// Supports DCHECK(cond) << "message" syntax via a sink type.

namespace folly {
namespace portability {
namespace detail {

struct DCheckStream {
	template<typename T>
	DCheckStream& operator<<(const T&) {
		return *this;
	}
};

// No-op log stream for LOG(severity) << ... (vendored Folly: no glog).
struct LogStream {
	template<typename T>
	LogStream& operator<<(const T&) {
		return *this;
	}
};

}  // namespace detail
}  // namespace portability
}  // namespace folly

#ifdef NDEBUG
#define FOLLY_GLOG_DCHECK_SINK() ::folly::portability::detail::DCheckStream()
#define DCHECK(condition) FOLLY_GLOG_DCHECK_SINK()
#define DCHECK_EQ(a, b) FOLLY_GLOG_DCHECK_SINK()
#define DCHECK_NE(a, b) FOLLY_GLOG_DCHECK_SINK()
#define DCHECK_GE(a, b) FOLLY_GLOG_DCHECK_SINK()
#define DCHECK_GT(a, b) FOLLY_GLOG_DCHECK_SINK()
#define DCHECK_LE(a, b) FOLLY_GLOG_DCHECK_SINK()
#define DCHECK_LT(a, b) FOLLY_GLOG_DCHECK_SINK()
#else
#define FOLLY_GLOG_DCHECK_SINK() ::folly::portability::detail::DCheckStream()
#define DCHECK(condition) \
	((condition) ? (void)0 : (void)assert(condition)), FOLLY_GLOG_DCHECK_SINK()
#define DCHECK_EQ(a, b) DCHECK((a) == (b))
#define DCHECK_NE(a, b) DCHECK((a) != (b))
#define DCHECK_GE(a, b) DCHECK((a) >= (b))
#define DCHECK_GT(a, b) DCHECK((a) > (b))
#define DCHECK_LE(a, b) DCHECK((a) <= (b))
#define DCHECK_LT(a, b) DCHECK((a) < (b))
#endif

// LOG(severity) - no-op in vendored build (no glog).
#define LOG(severity) ::folly::portability::detail::LogStream()

// CHECK* - same as DCHECK* (release: no-op sink; debug: assert).
#ifdef NDEBUG
#define CHECK(condition) FOLLY_GLOG_DCHECK_SINK()
#define CHECK_EQ(a, b) FOLLY_GLOG_DCHECK_SINK()
#define CHECK_NE(a, b) FOLLY_GLOG_DCHECK_SINK()
#define CHECK_GE(a, b) FOLLY_GLOG_DCHECK_SINK()
#define CHECK_GT(a, b) FOLLY_GLOG_DCHECK_SINK()
#define CHECK_LE(a, b) FOLLY_GLOG_DCHECK_SINK()
#define CHECK_LT(a, b) FOLLY_GLOG_DCHECK_SINK()
#define PCHECK(condition) FOLLY_GLOG_DCHECK_SINK()
#else
#define CHECK(condition) DCHECK(condition)
#define CHECK_EQ(a, b) DCHECK_EQ(a, b)
#define CHECK_NE(a, b) DCHECK_NE(a, b)
#define CHECK_GE(a, b) DCHECK_GE(a, b)
#define CHECK_GT(a, b) DCHECK_GT(a, b)
#define CHECK_LE(a, b) DCHECK_LE(a, b)
#define CHECK_LT(a, b) DCHECK_LT(a, b)
#define PCHECK(condition) DCHECK(condition)
#endif

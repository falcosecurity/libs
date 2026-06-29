
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

#include <sinsp_with_test_input.h>

// Regression guard for a use-after-free in sinsp_fdtable's single-entry LRU cache.
//
// sinsp_fdtable caches the last accessed fd as an OWNING std::shared_ptr
// (m_last_accessed_fdinfo). close_range() reaches sinsp_fdtable::retain() (via
// parse_close_range_exit) to drop fds in a range. retain() used to erase entries
// from the map WITHOUT invalidating that cache, unlike erase()/clear(). As a
// result, after close_range removed the cached fd, the cache still held the only
// owning reference to the freed map entry, and a subsequent get_fd() of the same
// fd returned a stale cache hit pointing at an entry no longer in the table.
//
// The dup2 exit parser is where this turns into a heap-use-after-free: it resolves
// evt.m_fdinfo (a raw, non-owning pointer) from the stale cache, then calls
// get_fd(newfd) which is a cache-miss + map-hit that OVERWRITES
// m_last_accessed_fdinfo, dropping the last owning shared_ptr and freeing the
// fdinfo that evt.m_fdinfo still points at. The next deref
// (evt.get_fd_info()->clone(), a virtual call) reads freed memory.
//
// The exact sequence below reproduces the original crash:
//   OPEN fd 40 -> OPEN fd 30 -> FSTAT_X(res=0, fd=30) [seeds the cache with fd 30]
//   -> CLOSE_RANGE_X(res=0, first=30, last=30, flags=0) [retain() removes fd 30]
//   -> DUP2_X(res=40, oldfd=30, newfd=40)
//
// With the retain() cache-invalidation fix in place:
//   - after close_range, get_fd(30) is a cache-miss + map-miss -> nullptr,
//   - dup2 exit takes the graceful early-return (evt.get_fd_info() == nullptr) and
//     never dereferences a dangling pointer.
//
// Without the fix, this test fails in two ways: the EXPECT_EQ below fails
// deterministically (close_range leaves the cache stale, so get_fd(30) returns
// a non-null dangling entry instead of nullptr), and the dup2 event below then
// dereferences the freed fdinfo. That dereference is caught reliably only under
// AddressSanitizer, which reports a heap-use-after-free READ; CI runs the
// libsinsp unit tests with -DUSE_ASAN=On (.github/workflows/ci.yml).
TEST_F(sinsp_with_test_input, CLOSE_RANGE_cached_fd_no_use_after_free) {
	add_default_init_thread();
	open_inspector();

	const auto tinfo = m_inspector.m_thread_manager->find_thread(INIT_TID, true);
	ASSERT_NE(tinfo, nullptr);

	// fd 40 must exist in the fd table so that the dup2 exit's get_fd(40) is a
	// map-HIT. That map-hit is what overwrites the LRU cache and frees fd 30's
	// fdinfo in the buggy path.
	constexpr int64_t newfd = 40;
	sinsp_test_input::open_params open_newfd{};
	open_newfd.fd = newfd;
	open_newfd.path = "/tmp/newfd.txt";
	ASSERT_TRUE(generate_open_x_event(open_newfd)->get_fd_info());
	ASSERT_TRUE(tinfo->get_fd(newfd));

	// fd 30 must exist in the fd table; it is the fd we close via close_range and
	// the one that must be the cached entry right before the close_range event.
	constexpr int64_t oldfd = 30;
	sinsp_test_input::open_params open_oldfd{};
	open_oldfd.fd = oldfd;
	open_oldfd.path = "/tmp/oldfd.txt";
	ASSERT_TRUE(generate_open_x_event(open_oldfd)->get_fd_info());
	ASSERT_TRUE(tinfo->get_fd(oldfd));

	// Seed the single-entry LRU cache with fd 30. Processing FSTAT_X(res=0, fd=30)
	// resolves fd 30 via a map-hit, which populates m_last_accessed_fd = 30 and
	// makes m_last_accessed_fdinfo the owning reference to fd 30's fdinfo.
	add_event_advance_ts(increasing_ts(),
	                     INIT_TID,
	                     PPME_SYSCALL_FSTAT_X,
	                     2,
	                     static_cast<int64_t>(0),  // res
	                     oldfd);                   // fd

	// close_range over [30, 30] reaches sinsp_fdtable::retain(), which removes fd
	// 30 from the map. Without the fix, the cache is left pointing at the removed
	// entry (m_last_accessed_fd stays 30).
	add_event_advance_ts(increasing_ts(),
	                     INIT_TID,
	                     PPME_SYSCALL_CLOSE_RANGE_X,
	                     4,
	                     static_cast<int64_t>(0),       // res
	                     static_cast<uint32_t>(oldfd),  // first
	                     static_cast<uint32_t>(oldfd),  // last
	                     static_cast<uint32_t>(0));     // flags

	// With the fix, fd 30 is gone AND the cache was invalidated, so get_fd(30) now
	// misses both the cache and the map and returns nullptr.
	//
	// This is a non-fatal EXPECT (not ASSERT) on purpose: without the fix, get_fd(30)
	// returns a stale (map-detached but not-yet-freed) cache pointer instead of
	// nullptr. We must NOT abort the test here, otherwise the dup2 event below (which
	// is what actually frees the fdinfo and triggers the use-after-free) would never
	// be processed and the regression would go undetected under AddressSanitizer.
	EXPECT_EQ(tinfo->get_fd(oldfd), nullptr);

	// dup2(oldfd=30 -> newfd=40), res = newfd = 40. This is the event that
	// triggers the heap-use-after-free in the buggy build (deref at the dup exit
	// parser's evt.get_fd_info()->clone()). With the fix it processes cleanly
	// because the dup exit parser sees evt.get_fd_info() == nullptr and returns
	// early.
	const auto dup2_evt = add_event_advance_ts(increasing_ts(),
	                                           INIT_TID,
	                                           PPME_SYSCALL_DUP2_X,
	                                           3,
	                                           newfd,   // res (return value == newfd)
	                                           oldfd,   // oldfd
	                                           newfd);  // newfd
	ASSERT_NE(dup2_evt, nullptr);

	// fd 40 is still present after the (no-op for the old fd) dup2 handling.
	ASSERT_TRUE(tinfo->get_fd(newfd));
}

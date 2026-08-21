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

// Tests for sinsp::open_raw_block(): the raw_block engine reuses the savefile block parser but
// reads blocks from a caller-owned in-memory buffer instead of a file. We build a small capture
// in memory, open it through sinsp::open_raw_block(), and read its events back. The buffer can be
// fed to the engine in three ways, all exercised here:
//   * whole-file:          the entire capture is visible at once,
//   * incremental replace: fed one chunk at a time, repointing the window and rewinding the reader
//                          with fseek(0) after each SCAP_EOF,
//   * incremental append:  fed one chunk at a time, growing the visible window after each SCAP_EOF.

#include <gtest/gtest.h>
#include <libsinsp/sinsp.h>
#include <libscap/scap.h>
#include <libscap/scap_savefile.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>

extern "C" uint32_t scap_event_has_large_payload(const scap_evt* e);

namespace {

// Append the native-order bytes of an integer. The Section Header Block magic is written in
// native order too, so the reader treats the whole capture as host byte order (no swap).
template<typename T>
void append(std::vector<uint8_t>& buf, T value) {
	const auto* p = reinterpret_cast<const uint8_t*>(&value);
	buf.insert(buf.end(), p, p + sizeof(T));
}

bool is_event_block_type(uint32_t block_type) {
	switch(block_type) {
	case EV_BLOCK_TYPE:
	case EV_BLOCK_TYPE_INT:
	case EV_BLOCK_TYPE_V2:
	case EV_BLOCK_TYPE_V2_LARGE:
	case EVF_BLOCK_TYPE:
	case EVF_BLOCK_TYPE_V2:
	case EVF_BLOCK_TYPE_V2_LARGE:
		return true;
	default:
		return false;
	}
}

// Minimal Section Header Block: enough preamble for the engine to reach the event blocks.
std::vector<uint8_t> build_shb() {
	std::vector<uint8_t> body;
	append<uint32_t>(body, SHB_MAGIC);              // byte_order_magic
	append<uint16_t>(body, CURRENT_MAJOR_VERSION);  // major_version
	append<uint16_t>(body, CURRENT_MINOR_VERSION);  // minor_version
	append<uint64_t>(body, UINT64_MAX);             // section_length (unspecified)

	const uint32_t total = sizeof(block_header) + static_cast<uint32_t>(body.size()) + 4;
	std::vector<uint8_t> out;
	append<uint32_t>(out, SHB_BLOCK_TYPE);
	append<uint32_t>(out, total);
	out.insert(out.end(), body.begin(), body.end());
	append<uint32_t>(out, total);  // trailing block_total_length
	return out;
}

// Encode a valid PPME_SYSCALL_CLOSE_X event. With its full parameter set it passes conversion
// unchanged, so the engine emits it verbatim.
scap_evt* encode_close_x(uint64_t res, uint64_t fd) {
	scap_sized_buffer buf = {nullptr, 0};
	size_t size = 0;
	char err[SCAP_LASTERR_SIZE] = {};
	int32_t rc = scap_event_encode_params(buf, &size, err, PPME_SYSCALL_CLOSE_X, 2, res, fd);
	EXPECT_EQ(rc, SCAP_INPUT_TOO_SMALL);
	buf.buf = malloc(size);
	buf.size = size;
	rc = scap_event_encode_params(buf, &size, err, PPME_SYSCALL_CLOSE_X, 2, res, fd);
	EXPECT_EQ(rc, SCAP_SUCCESS) << err;
	return static_cast<scap_evt*>(buf.buf);
}

// Wrap an encoded event into a savefile event block.
std::vector<uint8_t> wrap_event_block(const scap_evt* evt, uint16_t cpuid) {
	std::vector<uint8_t> body;
	append<uint16_t>(body, cpuid);
	const auto* evt_bytes = reinterpret_cast<const uint8_t*>(evt);
	body.insert(body.end(), evt_bytes, evt_bytes + evt->len);

	uint32_t total = sizeof(block_header) + static_cast<uint32_t>(body.size()) + 4;
	const uint32_t pad = (4 - (total % 4)) % 4;
	body.insert(body.end(), pad, 0u);
	total += pad;

	const uint32_t block_type =
	        scap_event_has_large_payload(evt) ? EV_BLOCK_TYPE_V2_LARGE : EV_BLOCK_TYPE_V2;
	std::vector<uint8_t> out;
	append<uint32_t>(out, block_type);
	append<uint32_t>(out, total);
	out.insert(out.end(), body.begin(), body.end());
	append<uint32_t>(out, total);  // trailing block_total_length
	return out;
}

// Build a capture: a section header block followed by `count` CLOSE_X event blocks. The i-th
// event has ts = ts_base + i and tid = tid_base + i so the reader output can be checked.
std::vector<uint8_t> build_capture(uint32_t count, uint64_t ts_base, uint64_t tid_base) {
	auto capture = build_shb();
	for(uint32_t i = 0; i < count; i++) {
		scap_evt* evt = encode_close_x(/*res*/ 0, /*fd*/ 3 + i);
		evt->ts = ts_base + i;
		evt->tid = tid_base + i;
		const auto block = wrap_event_block(evt, /*cpuid*/ 0);
		free(evt);
		capture.insert(capture.end(), block.begin(), block.end());
	}
	return capture;
}

// Offset of the first event block, i.e. the end of the section header + metadata blocks.
size_t first_event_block_offset(const std::vector<uint8_t>& data) {
	size_t offset = 0;
	while(offset + sizeof(block_header) <= data.size()) {
		block_header bh;
		memcpy(&bh, data.data() + offset, sizeof(bh));
		if(is_event_block_type(bh.block_type)) {
			return offset;
		}
		offset += bh.block_total_length;
	}
	return data.size();
}

// A decoded event, used to compare the modes' output.
struct event_record {
	uint16_t type;
	uint64_t ts;
	int64_t tid;

	bool operator==(const event_record& o) const {
		return type == o.type && ts == o.ts && tid == o.tid;
	}
};

enum class feed_mode { WHOLE_FILE, INCREMENTAL_REPLACE, INCREMENTAL_APPEND };

// Read the capture through sinsp::open_raw_block() using the given feed mode, returning the
// events read. In the incremental modes the engine is opened with only the section header
// visible, then fed one block at a time (a run of non-event blocks is fed together) as each
// SCAP_EOF is reached: INCREMENTAL_REPLACE repoints the window and rewinds the reader with
// fseek(0), INCREMENTAL_APPEND grows the window.
std::vector<event_record> read_raw_block(std::vector<uint8_t>& capture, feed_mode mode) {
	uint8_t* buffer_ptr = capture.data();
	uint64_t buffer_size = capture.size();
	size_t next_offset = capture.size();

	if(mode != feed_mode::WHOLE_FILE) {
		next_offset = first_event_block_offset(capture);
		buffer_size = next_offset;
	}

	sinsp inspector;
	inspector.open_raw_block(&buffer_ptr, &buffer_size);

	// On SCAP_EOF, expose the next chunk: one event block, or a whole run of non-event blocks.
	auto feed = [&]() -> bool {
		const size_t start = next_offset;
		if(start + sizeof(block_header) > capture.size()) {
			return false;
		}
		block_header bh;
		memcpy(&bh, capture.data() + start, sizeof(bh));
		size_t offset = start;
		if(is_event_block_type(bh.block_type)) {
			offset += bh.block_total_length;
		} else {
			while(offset + sizeof(block_header) <= capture.size()) {
				memcpy(&bh, capture.data() + offset, sizeof(bh));
				if(is_event_block_type(bh.block_type)) {
					break;
				}
				offset += bh.block_total_length;
			}
		}
		if(offset > capture.size()) {
			offset = capture.size();
		}

		if(mode == feed_mode::INCREMENTAL_APPEND) {
			buffer_ptr = capture.data();
			buffer_size = offset;
		} else {
			buffer_ptr = capture.data() + start;
			buffer_size = offset - start;
			inspector.fseek(0);
		}
		next_offset = offset;
		return true;
	};

	std::vector<event_record> records;
	for(;;) {
		sinsp_evt* evt = nullptr;
		const int32_t res = inspector.next(&evt);
		if(res == SCAP_TIMEOUT || res == SCAP_FILTERED_EVENT) {
			continue;
		}
		if(res == SCAP_SUCCESS) {
			EXPECT_NE(evt, nullptr);
			records.push_back({evt->get_type(), evt->get_ts(), evt->get_tid()});
			continue;
		}
		if(res == SCAP_EOF && mode != feed_mode::WHOLE_FILE && feed()) {
			continue;
		}
		if(res != SCAP_EOF) {
			ADD_FAILURE() << "unexpected next() result " << res << ": " << inspector.getlasterr();
		}
		break;
	}

	inspector.close();
	return records;
}

}  // namespace

// The three feed modes must all read back exactly the events that were written.
TEST(raw_block, feed_modes) {
	constexpr uint32_t count = 4;
	constexpr uint64_t ts_base = 1000;
	constexpr uint64_t tid_base = 100;
	auto capture = build_capture(count, ts_base, tid_base);

	std::vector<event_record> expected;
	for(uint32_t i = 0; i < count; i++) {
		expected.push_back({PPME_SYSCALL_CLOSE_X, ts_base + i, static_cast<int64_t>(tid_base + i)});
	}

	for(const auto mode :
	    {feed_mode::WHOLE_FILE, feed_mode::INCREMENTAL_REPLACE, feed_mode::INCREMENTAL_APPEND}) {
		SCOPED_TRACE(static_cast<int>(mode));
		EXPECT_EQ(read_raw_block(capture, mode), expected);
	}
}

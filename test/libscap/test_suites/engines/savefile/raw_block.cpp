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

// Basic test for the raw_block engine: it reuses the savefile block parser but reads blocks from
// an in-memory buffer instead of a file. We build a small capture in memory, open it with
// scap_open() through the raw_block engine, and read its event back.

#include <gtest/gtest.h>
#include <libscap/scap.h>
#include <libscap/scap_engines.h>
#include <libscap/scap_procs.h>
#include <libscap/scap_platform.h>
#include <libscap/scap_savefile.h>
#include <libscap/engine/raw_block/raw_block_public.h>

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

// Minimal Section Header Block: enough preamble for the engine to reach the event block.
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

}  // namespace

// Open an in-memory capture through the raw_block engine and read its single event.
TEST(savefile_raw_block, open_and_read) {
	scap_evt* evt = encode_close_x(/*res*/ 0, /*fd*/ 3);
	evt->ts = 1000;
	evt->tid = 100;
	auto capture = build_shb();
	const auto block = wrap_event_block(evt, /*cpuid*/ 0);
	free(evt);
	capture.insert(capture.end(), block.begin(), block.end());

	// The buffer and its (ptr, size) descriptor must outlive the handle.
	uint8_t* buffer_ptr = capture.data();
	uint64_t buffer_size = capture.size();

	scap_proc_callbacks callbacks{};
	callbacks.m_refresh_start_cb = default_refresh_start_end_callback;
	callbacks.m_refresh_end_cb = default_refresh_start_end_callback;
	callbacks.m_proc_entry_cb = default_proc_entry_callback;
	callbacks.m_callback_context = nullptr;

	scap_raw_block_engine_params params{};
	params.buffer_ptr = &buffer_ptr;
	params.buffer_size_ptr = &buffer_size;
	params.platform = scap_raw_block_alloc_platform(callbacks);

	scap_open_args oargs{};
	oargs.engine_params = &params;

	char error[SCAP_LASTERR_SIZE] = {};
	int32_t rc = SCAP_FAILURE;
	scap_t* h = scap_open(&oargs, &scap_raw_block_engine, error, &rc);
	ASSERT_NE(h, nullptr) << "scap_open (raw_block) failed: " << error;

	scap_evt* read_evt = nullptr;
	uint16_t devid = 0;
	uint32_t flags = 0;
	EXPECT_EQ(scap_next(h, &read_evt, &devid, &flags), SCAP_SUCCESS) << scap_getlasterr(h);
	ASSERT_NE(read_evt, nullptr);
	// scap_evt (ppm_evt_hdr) is packed, so use by-value accessors
	EXPECT_EQ(scap_event_get_type(read_evt), PPME_SYSCALL_CLOSE_X);
	EXPECT_EQ(scap_event_get_ts(read_evt), 1000u);
	EXPECT_EQ(scap_event_get_tid(read_evt), 100u);

	// Nothing else in the buffer: the next read is a clean EOF.
	EXPECT_EQ(scap_next(h, &read_evt, &devid, &flags), SCAP_EOF);

	scap_platform_close(params.platform);
	scap_platform_free(params.platform);
	scap_close(h);
}

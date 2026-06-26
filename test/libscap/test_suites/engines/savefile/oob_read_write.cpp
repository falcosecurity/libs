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

// Regression tests for a heap out-of-bounds read/write in the savefile parser.
//
// For EV_BLOCK_TYPE_V2 / EV_BLOCK_TYPE_V2_LARGE blocks the event header `len` is taken
// verbatim from the capture file. The conversion path used to memcpy `len` bytes into the
// fixed-size (MAX_EVENT_SIZE = 64 KiB) staging buffer without validating it, so a crafted
// `.scap` file could:
//   * Bug 1 (EV_BLOCK_TYPE_V2):       set `len` far beyond the bytes actually read, causing a
//                                     large heap OOB read and write.
//   * Bug 2 (EV_BLOCK_TYPE_V2_LARGE): set `len = MAX_EVENT_SIZE + N` with all bytes present in
//                                     the (reallocated) reader buffer, causing a controlled
//                                     N-byte heap OOB write past the staging buffer.
//
// The fix bounds `len` against the bytes available in the block (next_event_from_file) and
// validates the V2 length table before conversion. The conversion loop also rejects events larger
// than MAX_EVENT_SIZE before copying them into fixed-size staging buffers. These tests build such
// files in memory, read them through the savefile engine, and assert the crafted event is rejected
// with a clean SCAP_FAILURE instead of corrupting memory (the OOB is also caught by ASan).

#include <gtest/gtest.h>
#include <libscap/scap.h>
#include <libscap/scap_engines.h>
#include <libscap/scap_procs.h>
#include <libscap/scap_platform.h>
#include <libscap/scap_savefile.h>
#include <libscap/engine/savefile/savefile_public.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include <unistd.h>

namespace {

// MAX_EVENT_SIZE is private to scap_savefile.c; keep a local copy in sync. The savefile
// reader buffer (READER_BUF_SIZE) is intentionally the same size, which is why Bug 2 works.
constexpr uint32_t MAX_EVENT_SIZE = 64 * 1024;
// ppm_evt_hdr = ts(8) + tid(8) + len(4) + type(2) + nparams(4).
constexpr uint32_t PPM_EVT_HDR_SIZE = 26;

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

// Build a single event block carrying an attacker-chosen `evt_len`/`nparams`.
std::vector<uint8_t> event_block(uint32_t block_type,
                                 uint16_t cpuid,
                                 uint32_t evt_len,
                                 uint16_t evt_type,
                                 uint32_t nparams,
                                 const std::vector<uint8_t>& payload,
                                 bool pad_to_4) {
	std::vector<uint8_t> body;
	append<uint16_t>(body, cpuid);
	append<uint64_t>(body, /*ts*/ 1);
	append<uint64_t>(body, /*tid*/ 0);
	append<uint32_t>(body, evt_len);
	append<uint16_t>(body, evt_type);
	append<uint32_t>(body, nparams);
	body.insert(body.end(), payload.begin(), payload.end());

	uint32_t total = sizeof(block_header) + static_cast<uint32_t>(body.size()) + 4;
	if(pad_to_4) {
		const uint32_t pad = (4 - (total % 4)) % 4;
		body.insert(body.end(), pad, 0u);
		total += pad;
	}

	std::vector<uint8_t> out;
	append<uint32_t>(out, block_type);
	append<uint32_t>(out, total);
	out.insert(out.end(), body.begin(), body.end());
	append<uint32_t>(out, total);  // trailing block_total_length
	return out;
}

// Write the bytes to a throwaway file and return its path.
std::string write_temp_capture(const std::vector<uint8_t>& bytes) {
	char path[] = "/tmp/scap_oob_XXXXXX";
	const int fd = mkstemp(path);
	EXPECT_GE(fd, 0) << "cannot create temp capture";
	if(fd < 0) {
		return {};
	}
	const ssize_t written = write(fd, bytes.data(), bytes.size());
	EXPECT_EQ(static_cast<size_t>(written), bytes.size());
	close(fd);
	return path;
}

// Open the crafted capture through the savefile engine and return the result of reading the
// first event, along with the last error string. The crafted event is the first (and only)
// event, so a correct parser must reject it here rather than crash.
int32_t read_first_event(const std::vector<uint8_t>& capture, std::string& lasterr) {
	const std::string path = write_temp_capture(capture);
	if(path.empty()) {
		return SCAP_FAILURE;
	}

	scap_proc_callbacks callbacks{};
	callbacks.m_refresh_start_cb = default_refresh_start_end_callback;
	callbacks.m_refresh_end_cb = default_refresh_start_end_callback;
	callbacks.m_proc_entry_cb = default_proc_entry_callback;
	callbacks.m_callback_context = nullptr;

	scap_savefile_engine_params params{};
	params.fname = path.c_str();
	params.platform = scap_savefile_alloc_platform(callbacks);

	scap_open_args oargs{};
	oargs.engine_params = &params;

	char error[SCAP_LASTERR_SIZE] = {};
	int32_t rc = SCAP_FAILURE;
	scap_t* h = scap_open(&oargs, &scap_savefile_engine, error, &rc);
	// The SHB + event preamble is well-formed, so opening must succeed; the crafted event is
	// only inspected on the first scap_next().
	EXPECT_NE(h, nullptr) << "scap_open failed: " << error;

	int32_t res = rc;
	if(h != nullptr) {
		scap_evt* evt = nullptr;
		uint16_t devid = 0;
		uint32_t flags = 0;
		res = scap_next(h, &evt, &devid, &flags);
		lasterr = scap_getlasterr(h);
	}

	// The caller owns the platform allocated above; free it as libsinsp does on close.
	scap_platform_close(params.platform);
	scap_platform_free(params.platform);
	if(h != nullptr) {
		scap_close(h);
	}
	remove(path.c_str());
	return res;
}

}  // namespace

// Bug 1: EV_BLOCK_TYPE_V2 with `len` far larger than the bytes read for the block.
// Rejected by the in-buffer bound in next_event_from_file().
TEST(savefile_oob, ev_v2_len_exceeds_block) {
	auto capture = build_shb();
	const auto block = event_block(EV_BLOCK_TYPE_V2,
	                               /*cpuid*/ 0,
	                               /*evt_len*/ 5'832'704,  // ~5.8 MiB, block holds < 64 bytes
	                               /*evt_type*/ PPME_SYSCALL_OPEN_E,
	                               /*nparams*/ 524'288,
	                               /*payload*/ {},
	                               /*pad_to_4*/ true);
	capture.insert(capture.end(), block.begin(), block.end());

	std::string lasterr;
	const int32_t res = read_first_event(capture, lasterr);
	EXPECT_EQ(res, SCAP_FAILURE) << "oversized V2 event should be rejected";
	EXPECT_NE(lasterr.find("invalid event"), std::string::npos) << "unexpected error: " << lasterr;
}

// Bug 2 (crash variant): EV_BLOCK_TYPE_V2_LARGE whose `len` exceeds the bytes actually read.
// Also rejected by the in-buffer bound in next_event_from_file().
TEST(savefile_oob, ev_v2_large_len_exceeds_block) {
	auto capture = build_shb();
	const auto block = event_block(EV_BLOCK_TYPE_V2_LARGE,
	                               /*cpuid*/ 0,
	                               /*evt_len*/ 196'608,  // 0x30000, block holds < 64 bytes
	                               /*evt_type*/ PPME_GENERIC_E,
	                               /*nparams*/ 2'490'368,
	                               /*payload*/ {},
	                               /*pad_to_4*/ false);
	capture.insert(capture.end(), block.begin(), block.end());

	std::string lasterr;
	const int32_t res = read_first_event(capture, lasterr);
	EXPECT_EQ(res, SCAP_FAILURE) << "oversized V2_LARGE event should be rejected";
	EXPECT_NE(lasterr.find("invalid event"), std::string::npos) << "unexpected error: " << lasterr;
}

// Bug 2 (controlled-write variant): EV_BLOCK_TYPE_V2_LARGE where every byte of `len` is present
// in the (reallocated) reader buffer, but `len > MAX_EVENT_SIZE`. This passes the in-buffer
// bound and must be stopped by the MAX_EVENT_SIZE bound on the conversion path before the
// memcpy into the fixed-size staging buffer. A converter-managed enter event (PPME_GENERIC_E)
// forces the conversion (CONVERSION_CONTINUE) that reaches the memcpy.
TEST(savefile_oob, ev_v2_large_len_exceeds_max_event_size) {
	constexpr uint32_t overflow = 64;
	const uint32_t evt_len = MAX_EVENT_SIZE + overflow;
	constexpr uint16_t first_param_len = 32785;
	constexpr uint16_t second_param_len = 32785;

	// Make the block carry exactly `evt_len` event bytes so the in-buffer bound passes and the
	// event reaches the conversion path. 0x42 marks the bytes that would overflow.
	std::vector<uint8_t> payload;
	payload.reserve(sizeof(uint16_t) * 2 + first_param_len + second_param_len);
	append<uint16_t>(payload, first_param_len);
	append<uint16_t>(payload, second_param_len);
	for(uint32_t i = 0; i < first_param_len + second_param_len; i++) {
		payload.push_back(i < first_param_len + second_param_len - overflow ? 0x41 : 0x42);
	}

	auto capture = build_shb();
	const auto block = event_block(EV_BLOCK_TYPE_V2_LARGE,
	                               /*cpuid*/ 0,
	                               evt_len,
	                               /*evt_type*/ PPME_GENERIC_E,
	                               /*nparams*/ 2,
	                               payload,
	                               /*pad_to_4*/ false);
	capture.insert(capture.end(), block.begin(), block.end());

	std::string lasterr;
	const int32_t res = read_first_event(capture, lasterr);
	EXPECT_EQ(res, SCAP_FAILURE) << "V2_LARGE event over MAX_EVENT_SIZE should be rejected";
	EXPECT_NE(lasterr.find("invalid event"), std::string::npos) << "unexpected error: " << lasterr;
}

// A valid-size event can still overflow the conversion output buffer if conversion adds parameters
// and shifts the existing parameter blob forward.
TEST(savefile_oob, ev_v2_large_conversion_expansion_exceeds_max_event_size) {
	constexpr uint32_t param_len = MAX_EVENT_SIZE - PPM_EVT_HDR_SIZE - sizeof(uint16_t);

	std::vector<uint8_t> payload;
	payload.reserve(sizeof(uint16_t) + param_len);
	append<uint16_t>(payload, param_len);
	for(uint32_t i = 0; i < param_len; i++) {
		payload.push_back(0x41);
	}

	auto capture = build_shb();
	const auto block = event_block(EV_BLOCK_TYPE_V2_LARGE,
	                               /*cpuid*/ 0,
	                               MAX_EVENT_SIZE,
	                               /*evt_type*/ PPME_GENERIC_X,
	                               /*nparams*/ 1,
	                               payload,
	                               /*pad_to_4*/ false);
	capture.insert(capture.end(), block.begin(), block.end());

	std::string lasterr;
	const int32_t res = read_first_event(capture, lasterr);
	EXPECT_EQ(res, SCAP_FAILURE) << "conversion expansion past MAX_EVENT_SIZE should be rejected";
	EXPECT_NE(lasterr.find("conversion buffer"), std::string::npos)
	        << "unexpected error: " << lasterr;
}

// The V2 `nparams` field is attacker-controlled too. If the declared length table cannot fit
// inside `len`, conversion must reject the event before using `nparams` in offset calculations.
TEST(savefile_oob, ev_v2_nparams_exceeds_event_len) {
	auto capture = build_shb();
	const auto block = event_block(EV_BLOCK_TYPE_V2,
	                               /*cpuid*/ 0,
	                               PPM_EVT_HDR_SIZE,
	                               /*evt_type*/ PPME_GENERIC_X,
	                               /*nparams*/ 257,
	                               /*payload*/ {},
	                               /*pad_to_4*/ true);
	capture.insert(capture.end(), block.begin(), block.end());

	std::string lasterr;
	const int32_t res = read_first_event(capture, lasterr);
	EXPECT_EQ(res, SCAP_FAILURE) << "V2 event with impossible nparams should be rejected";
	EXPECT_NE(lasterr.find("invalid event"), std::string::npos) << "unexpected error: " << lasterr;
}

// Even when the length table fits, individual parameter lengths must stay inside event->len.
TEST(savefile_oob, ev_v2_param_len_exceeds_event_len) {
	std::vector<uint8_t> payload;
	append<uint16_t>(payload, UINT16_MAX);

	auto capture = build_shb();
	const auto block = event_block(EV_BLOCK_TYPE_V2,
	                               /*cpuid*/ 0,
	                               PPM_EVT_HDR_SIZE + static_cast<uint32_t>(payload.size()),
	                               /*evt_type*/ PPME_GENERIC_X,
	                               /*nparams*/ 1,
	                               payload,
	                               /*pad_to_4*/ true);
	capture.insert(capture.end(), block.begin(), block.end());

	std::string lasterr;
	const int32_t res = read_first_event(capture, lasterr);
	EXPECT_EQ(res, SCAP_FAILURE) << "V2 event with oversized param len should be rejected";
	EXPECT_NE(lasterr.find("invalid event"), std::string::npos) << "unexpected error: " << lasterr;
}

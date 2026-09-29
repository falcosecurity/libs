// SPDX-License-Identifier: Apache-2.0
/* Copyright (C) 2026 The Falco Authors. */

#include <gtest/gtest.h>
#include <libscap/scap.h>
#include <libscap/scap_engines.h>
#include <libscap/scap_procs.h>
#include <libscap/scap_platform.h>
#include <libscap/scap_savefile.h>
#include <libscap/engine/savefile/savefile_public.h>

#include <cstdint>
#include <string>
#include <vector>
#include <unistd.h>

namespace {
template<typename T>
void append(std::vector<uint8_t>& buf, T value) {
	const auto* p = reinterpret_cast<const uint8_t*>(&value);
	buf.insert(buf.end(), p, p + sizeof(T));
}

std::vector<uint8_t> section_header() {
	std::vector<uint8_t> body;
	append<uint32_t>(body, SHB_MAGIC);
	append<uint16_t>(body, CURRENT_MAJOR_VERSION);
	append<uint16_t>(body, CURRENT_MINOR_VERSION);
	append<uint64_t>(body, UINT64_MAX);
	const uint32_t total = sizeof(block_header) + body.size() + sizeof(uint32_t);
	std::vector<uint8_t> out;
	append<uint32_t>(out, SHB_BLOCK_TYPE);
	append<uint32_t>(out, total);
	out.insert(out.end(), body.begin(), body.end());
	append<uint32_t>(out, total);
	return out;
}

void append_fname(std::vector<uint8_t>& record, const std::string& name) {
	append<uint16_t>(record, static_cast<uint16_t>(name.size()));
	record.insert(record.end(), name.begin(), name.end());
}

std::vector<uint8_t> unix_record() {
	std::vector<uint8_t> payload;
	append<int64_t>(payload, 3);
	append<uint64_t>(payload, 10);
	append<uint8_t>(payload, SCAP_FD_UNIX_SOCK);
	append<uint64_t>(payload, 1);
	append<uint64_t>(payload, 2);
	// Fill the whole union, including the bytes that map to regularinfo.mount_id/dev.
	append_fname(payload, std::string(SCAP_MAX_PATH_SIZE - 1, static_cast<char>(0x5a)));
	std::vector<uint8_t> record;
	append<uint32_t>(record, static_cast<uint32_t>(payload.size() + sizeof(uint32_t)));
	record.insert(record.end(), payload.begin(), payload.end());
	return record;
}

std::vector<uint8_t> short_file_v2_record() {
	std::vector<uint8_t> payload;
	append<int64_t>(payload, 4);
	append<uint64_t>(payload, 11);
	append<uint8_t>(payload, SCAP_FD_FILE_V2);
	append<uint32_t>(payload, 0);
	append_fname(payload, "x");
	// Old captures may end here, before dev; mount_id is never serialized.
	std::vector<uint8_t> record;
	append<uint32_t>(record, static_cast<uint32_t>(payload.size() + sizeof(uint32_t)));
	record.insert(record.end(), payload.begin(), payload.end());
	return record;
}

std::vector<uint8_t> fdlist_block() {
	std::vector<uint8_t> body;
	append<uint64_t>(body, 123);
	for(const auto& record : {unix_record(), short_file_v2_record()}) {
		body.insert(body.end(), record.begin(), record.end());
	}
	while((sizeof(block_header) + body.size() + sizeof(uint32_t)) % 4 != 0) {
		body.push_back(0);
	}
	const uint32_t total = sizeof(block_header) + body.size() + sizeof(uint32_t);
	std::vector<uint8_t> out;
	append<uint32_t>(out, FDL_BLOCK_TYPE_V2);
	append<uint32_t>(out, total);
	out.insert(out.end(), body.begin(), body.end());
	append<uint32_t>(out, total);
	return out;
}

std::vector<uint8_t> event_block() {
	std::vector<uint8_t> body;
	append<uint16_t>(body, 0);
	append<uint64_t>(body, 1);
	append<uint64_t>(body, 123);
	append<uint32_t>(body, 26);
	append<uint16_t>(body, PPME_GENERIC_E);
	append<uint32_t>(body, 0);
	while((sizeof(block_header) + body.size() + sizeof(uint32_t)) % 4 != 0)
		body.push_back(0);
	const uint32_t total = sizeof(block_header) + body.size() + sizeof(uint32_t);
	std::vector<uint8_t> out;
	append<uint32_t>(out, EV_BLOCK_TYPE_V2);
	append<uint32_t>(out, total);
	out.insert(out.end(), body.begin(), body.end());
	append<uint32_t>(out, total);
	return out;
}

int32_t collect_fds(void* context,
                    char*,
                    int64_t,
                    scap_threadinfo*,
                    scap_fdinfo* fdinfo,
                    scap_threadinfo**) {
	if(fdinfo != nullptr)
		static_cast<std::vector<scap_fdinfo>*>(context)->push_back(*fdinfo);
	return SCAP_SUCCESS;
}
}  // namespace

TEST(savefile_fdlist, clears_missing_fields_between_records) {
	auto capture = section_header();
	for(const auto& block : {fdlist_block(), event_block()})
		capture.insert(capture.end(), block.begin(), block.end());
	char path[] = "/tmp/scap_fd_init_XXXXXX";
	const int fd = mkstemp(path);
	ASSERT_GE(fd, 0);
	ASSERT_EQ(write(fd, capture.data(), capture.size()), static_cast<ssize_t>(capture.size()));
	close(fd);

	std::vector<scap_fdinfo> fds;
	scap_proc_callbacks callbacks{};
	callbacks.m_refresh_start_cb = default_refresh_start_end_callback;
	callbacks.m_refresh_end_cb = default_refresh_start_end_callback;
	callbacks.m_proc_entry_cb = collect_fds;
	callbacks.m_callback_context = &fds;
	scap_savefile_engine_params params{};
	params.fname = path;
	params.platform = scap_savefile_alloc_platform(callbacks);
	scap_open_args args{};
	args.engine_params = &params;
	char error[SCAP_LASTERR_SIZE] = {};
	int32_t rc = SCAP_FAILURE;
	scap_t* h = scap_open(&args, &scap_savefile_engine, error, &rc);
	ASSERT_NE(h, nullptr) << error;
	ASSERT_EQ(fds.size(), 2u);
	EXPECT_EQ(fds[1].type, SCAP_FD_FILE_V2);
	EXPECT_EQ(fds[1].info.regularinfo.mount_id, 0u);
	EXPECT_EQ(fds[1].info.regularinfo.dev, 0u);
	scap_close(h);
	scap_platform_close(params.platform);
	scap_platform_free(params.platform);
	remove(path);
}

// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2026 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

/**
 * extract_scap_events - Extract raw scap events from a capture file for fuzz corpus.
 *
 * Reads a .scap savefile and writes individual events as binary files into an
 * output directory. Events are filtered by max_len (skipped if too small or too
 * large). Used to build seed corpora for fuzz_scap_event_decode and similar
 * fuzzers that consume raw scap_evt buffers.
 *
 * Usage: extract_scap_events <input.scap> <output_dir> <max_events> <max_len>
 */

#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#include <libscap/scap.h>
#include <libscap/scap_engines.h>
#include <libscap/scap_platform.h>

int main(int argc, char** argv) {
	if(argc < 5) {
		std::cerr << "usage: " << argv[0] << " <input.scap> <output_dir> <max_events> <max_len>\n";
		return 1;
	}

	// Parse arguments: input capture file, output directory, cap on events to write, max event size
	const std::string input = argv[1];
	const std::filesystem::path outdir = argv[2];
	const int max_events = std::stoi(argv[3]);
	const uint32_t max_len = static_cast<uint32_t>(std::stoul(argv[4]));

	std::error_code ec;
	std::filesystem::create_directories(outdir, ec);
	if(ec) {
		std::cerr << "failed to create output dir: " << ec.message() << "\n";
		return 1;
	}

	// Set up savefile engine: platform with empty proc callbacks (no live process table needed)
	scap_proc_callbacks callbacks = {};
	auto* platform = scap_savefile_alloc_platform(callbacks);
	if(platform == nullptr) {
		std::cerr << "failed to allocate savefile platform\n";
		return 1;
	}

	scap_open_args oargs = {};
	scap_savefile_engine_params params = {};
	params.fname = input.c_str();
	params.platform = platform;
	oargs.engine_params = &params;

	char error[SCAP_LASTERR_SIZE] = {0};
	int32_t rc = SCAP_FAILURE;
	scap_t* h = scap_open(&oargs, &scap_savefile_engine, error, &rc);
	if(h == nullptr || rc != SCAP_SUCCESS) {
		std::cerr << "scap_open failed: " << error << " (" << rc << ")\n";
		scap_platform_free(platform);
		return 1;
	}

	rc = scap_start_capture(h);
	if(rc != SCAP_SUCCESS) {
		std::cerr << "scap_start_capture failed: " << scap_getlasterr(h) << " (" << rc << ")\n";
		scap_close(h);
		scap_platform_free(platform);
		return 1;
	}

	// Read events until we've written max_events or hit EOF
	int written = 0;
	int seen = 0;
	while(written < max_events) {
		scap_evt* ev = nullptr;
		uint16_t cpuid = 0;
		uint32_t flags = 0;
		rc = scap_next(h, &ev, &cpuid, &flags);

		if(rc == SCAP_TIMEOUT || rc == SCAP_FILTERED_EVENT) {
			continue;
		}
		if(rc == SCAP_EOF) {
			break;
		}
		if(rc != SCAP_SUCCESS) {
			std::cerr << "scap_next failed: " << scap_getlasterr(h) << " (" << rc << ")\n";
			scap_close(h);
			scap_platform_free(platform);
			return 1;
		}

		++seen;
		// Skip events that are invalid or outside the fuzzer's accepted size range
		if(ev == nullptr || ev->len < sizeof(scap_evt) || ev->len > max_len) {
			continue;
		}

		// Write one binary file per event: evt_<index>_type<type>_len<len>.bin
		std::ostringstream name;
		name << "evt_" << written << "_type" << ev->type << "_len" << ev->len << ".bin";
		const auto outpath = outdir / name.str();

		std::ofstream ofs(outpath, std::ios::binary);
		if(!ofs) {
			std::cerr << "failed to open output file: " << outpath << "\n";
			scap_close(h);
			scap_platform_free(platform);
			return 1;
		}
		ofs.write(reinterpret_cast<const char*>(ev), ev->len);
		if(!ofs.good()) {
			std::cerr << "failed to write output file: " << outpath << "\n";
			scap_close(h);
			scap_platform_free(platform);
			return 1;
		}
		++written;
	}

	std::cout << "seen=" << seen << " written=" << written << "\n";
	scap_close(h);
	scap_platform_free(platform);
	return 0;
}

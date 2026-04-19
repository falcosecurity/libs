// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2026 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

/**
 * Fuzz target for scap_event_decode_params().
 *
 * Input: [1B control][26B scap_evt header][length table][param payload]
 *
 * The first byte is harness-only. It lets the fuzzer steer mutated inputs
 * toward a few useful event schemas and optionally ask for header nparams to
 * be larger than the schema count.
 *
 * The remaining bytes are treated as one raw scap_evt buffer. We patch a few
 * header fields so libscap sees a self-consistent event, call
 * scap_event_decode_params(), then perform small guarded reads through the
 * decoded parameter ranges. This exercises decode + basic consume paths
 * without letting obviously wild mutations dominate the run immediately.
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include <driver/ppm_events_public.h>
#include <libscap/scap.h>

namespace {

// The decoder behavior depends heavily on the event schema. These fixed sets
// give libFuzzer a small menu of useful schemas to target on purpose.
//
// Regular events use 16-bit param lengths. The chosen set spans small events
// and larger ones up near PPM_MAX_EVENT_PARAMS.
constexpr std::array<ppm_event_code, 10> kRegularEventTypes = {
        PPME_GENERIC_X,
        PPME_SYSCALL_OPEN_X,
        PPME_SYSCALL_READ_X,
        PPME_SOCKET_SENDTO_X,
        PPME_SYSCALL_CLOSE_X,
        PPME_SYSCALL_WRITE_X,
        PPME_SOCKET_CONNECT_X,
        PPME_PROCEXIT_1_E,
        PPME_SYSCALL_CLONE_20_X,
        PPME_SYSCALL_EXECVE_19_X,
};

constexpr std::array<ppm_event_code, 3> kLargePayloadEventTypes = {
        PPME_PLUGINEVENT_E,
        PPME_CONTAINER_JSON_2_E,
        PPME_ASYNCEVENT_E,
};

// Bits [1:0] choose how much the harness should steer the event type.
// 0 = pass the mutated type through, 1 = choose from regular events,
// 2 = choose from large-payload events, 3 = choose from either set.
ppm_event_code pick_event_type(uint8_t control, uint16_t raw_type) {
	switch(control & 0x03) {
	case 1:
		return kRegularEventTypes[(control >> 2) % kRegularEventTypes.size()];
	case 2:
		return kLargePayloadEventTypes[(control >> 2) % kLargePayloadEventTypes.size()];
	case 3:
		if((control & 0x80) != 0) {
			return kLargePayloadEventTypes[(control >> 2) % kLargePayloadEventTypes.size()];
		}
		return kRegularEventTypes[(control >> 2) % kRegularEventTypes.size()];
	default:
		return (ppm_event_code)(raw_type % PPM_EVENT_MAX);
	}
}

// libFuzzer mutates raw bytes freely, so the header often starts out
// self-contradictory. Normalize the fields that matter for decode:
//   - len should match the actual buffer size
//   - type should land on a real event schema
//   - nparams should fit in the available buffer
//
// We optionally let header nparams exceed the schema count so the decoder has
// to take its internal clamp path. Returns the final header nparams.
uint32_t fixup_event_header(scap_evt* event, uint8_t control, size_t buf_size) {
	event->len = (uint32_t)buf_size;
	event->type = (uint16_t)pick_event_type(control, event->type);

	const ppm_event_info* info = scap_event_getinfo(event);
	bool is_large = (info->flags & EF_LARGE_PAYLOAD) != 0;
	uint32_t entry_size = is_large ? 4 : 2;

	// Even before schema rules are applied, the length table cannot describe
	// more parameters than physically fit after the event header.
	uint32_t max_nparams = 0;
	if(buf_size > sizeof(scap_evt)) {
		max_nparams = (uint32_t)((buf_size - sizeof(scap_evt)) / entry_size);
	}
	if(max_nparams > PPM_MAX_EVENT_PARAMS) {
		max_nparams = PPM_MAX_EVENT_PARAMS;
	}

	// When bit 6 is set, push header nparams above the schema count on purpose.
	// The decoder should clamp that back down safely.
	bool inflate = (control & 0x40) != 0;
	if(inflate && max_nparams > info->nparams) {
		uint32_t extra = 1 + ((control >> 3) & 0x07);
		uint32_t wanted = info->nparams + extra;
		event->nparams = (wanted < max_nparams) ? wanted : max_nparams;
	} else {
		event->nparams = (event->nparams < max_nparams) ? event->nparams : max_nparams;
	}

	return event->nparams;
}

// Touch the decoder-returned parameter ranges so the harness exercises more
// than just "decoder returned". We keep the reads guarded: if a pointer is
// clearly outside this input buffer, we skip it instead of crashing on the
// spot. That tradeoff keeps the target stable enough to explore while still
// covering the normal decode + basic access path.
void touch_decoded_params(const scap_sized_buffer* params,
                          uint32_t n,
                          const uint8_t* buf_start,
                          const uint8_t* buf_end) {
	volatile uint8_t sink = 0;

	for(uint32_t i = 0; i < n; i++) {
		auto* ptr = (const uint8_t*)params[i].buf;
		size_t len = params[i].size;

		if(len == 0 || ptr == nullptr) {
			continue;
		}
		if(ptr < buf_start || ptr >= buf_end) {
			continue;
		}

		size_t avail = (size_t)(buf_end - ptr);
		size_t touch_len = (len < avail) ? len : avail;
		sink ^= ptr[0];
		if(touch_len > 1) {
			sink ^= ptr[touch_len - 1];
		}
	}

	(void)sink;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	// Need at least a control byte plus a full scap_evt header.
	if(size < 1 + sizeof(scap_evt)) {
		return 0;
	}
	const uint8_t control = data[0];
	data += 1;
	size -= 1;

	// Cap individual input size so the target stays fast and focused.
	if(size > (1U << 16)) {
		size = (1U << 16);
	}

	// Work on a mutable copy because we normalize header fields before decode.
	std::vector<uint8_t> buf(data, data + size);
	auto* event = reinterpret_cast<scap_evt*>(buf.data());

	uint32_t nparams = fixup_event_header(event, control, size);

	// Run the decoder. We still call it when nparams == 0 so the "zero params"
	// path is exercised too.
	std::vector<scap_sized_buffer> params(nparams);
	uint32_t n_decoded = scap_event_decode_params(event, params.data());

	if(nparams == 0) {
		return 0;
	}

	// Follow the decoded ranges back into this input buffer when they are still
	// safe to touch.
	uint32_t n = (n_decoded < nparams) ? n_decoded : nparams;
	touch_decoded_params(params.data(), n, buf.data(), buf.data() + size);

	return 0;
}

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <vector>

#include <driver/ppm_events_public.h>
#include <libscap/scap.h>

// Fuzzes libscap parameter decoding from a raw scap_evt-shaped byte buffer.
//
// Design goals:
// 1. Keep harness behavior deterministic and bounded.
// 2. Avoid harness-induced out-of-bounds reads that hide target bugs.
// 3. Still allow malformed layouts so parser error paths are exercised.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	// Need at least the event header to do meaningful work.
	if(size < sizeof(scap_evt)) {
		return 0;
	}

	// Keep per-exec work bounded while still allowing reasonably large events.
	if(size > (1U << 16)) {
		size = (1U << 16);
	}

	std::vector<uint8_t> evbuf(data, data + size);
	auto* ev = reinterpret_cast<scap_evt*>(evbuf.data());

	// Constrain key header fields so libscap decoders read within our input.
	// - len must match the actual buffer length.
	// - type must map to a valid event metadata entry.
	ev->len = static_cast<uint32_t>(size);
	ev->type = static_cast<uint16_t>(ev->type % PPM_EVENT_MAX);

	const ppm_event_info* info = scap_event_getinfo(ev);
	// Some events use 16-bit length entries, others 32-bit for large payloads.
	const uint32_t len_size =
	        (info->flags & EF_LARGE_PAYLOAD) ? sizeof(uint32_t) : sizeof(uint16_t);

	// nparams drives length-table parsing; clamp it to both schema and buffer limits.
	uint32_t max_nparams = 0;
	if(size > sizeof(scap_evt) && len_size > 0) {
		// Max number of length entries we can read without leaving the input buffer.
		max_nparams = static_cast<uint32_t>((size - sizeof(scap_evt)) / len_size);
	}
	// Clamp fuzzer-controlled nparams against:
	// 1) declared metadata for this event type, and
	// 2) physically possible entries in the current buffer.
	ev->nparams = std::min(ev->nparams, std::min<uint32_t>(info->nparams, max_nparams));

	if(ev->nparams == 0) {
		// No parameters to decode for this testcase after clamping.
		return 0;
	}

	std::vector<scap_sized_buffer> params(ev->nparams);
	// Target API under test.
	const uint32_t decoded = scap_event_decode_params(ev, params.data());

	// Touch decoded parameter boundaries when they still point within our buffer.
	// This prevents aggressive optimization from discarding decode results and helps
	// keep boundary-sensitive paths observable to the fuzzer.
	size_t cur = sizeof(scap_evt) + static_cast<size_t>(len_size) * ev->nparams;
	for(uint32_t i = 0; i < decoded && i < params.size(); ++i) {
		// Stop once a decoded param range would exceed input boundaries.
		if(params[i].size > size || cur > size - params[i].size) {
			break;
		}
		if(params[i].size > 0) {
			volatile uint8_t sink = 0;
			const auto* p = reinterpret_cast<const uint8_t*>(params[i].buf);
			sink ^= p[0];
			sink ^= p[params[i].size - 1];
			(void)sink;
		}
		cur += params[i].size;
	}

	return 0;
}

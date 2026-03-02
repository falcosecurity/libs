// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2026 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

/**
 * Fuzz target for scap event decoding (scap_event_decode_params).
 *
 * Each libFuzzer input is treated as a single raw scap_evt buffer. Layout:
 *   [scap_evt header][param length 0][param length 1]...[param payload bytes...]
 * The header has len, type, nparams; the length table gives the size of each
 * parameter; the payload region holds the actual parameter data. This fuzzer
 * exercises the code that decodes those boundaries and validates them against
 * the buffer, and then touches decoder-returned parameter buffers so the fuzzer
 * can reach bugs in boundary computation or out-of-bounds access.
 */

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <vector>

#include <driver/ppm_events_public.h>
#include <libscap/scap.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // Reject inputs too small to hold a valid event header.
  if (size < sizeof(scap_evt)) {
    return 0;
  }

  // Cap input size so a single run stays fast; libFuzzer prefers small inputs.
  const size_t max_input_size = (1U << 16);
  if (size > max_input_size) {
    size = max_input_size;
  }

  // Work on a mutable copy so we can fix up the header for the decoder.
  std::vector<uint8_t> event_bytes(data, data + size);
  auto* event = reinterpret_cast<scap_evt*>(event_bytes.data());

  // Make header consistent with the actual buffer: len = size, type in valid range.
  event->len = static_cast<uint32_t>(size);
  event->type = static_cast<uint16_t>(event->type % PPM_EVENT_MAX);

  // Parameter length table: 2 bytes per param for normal events, 4 for EF_LARGE_PAYLOAD.
  const ppm_event_info* event_info = scap_event_getinfo(event);
  const uint32_t parameter_length_entry_size =
      (event_info->flags & EF_LARGE_PAYLOAD) ? sizeof(uint32_t) : sizeof(uint16_t);

  // How many length slots fit after the header (upper bound for nparams).
  uint32_t max_length_entries_in_buffer = 0;
  if (size > sizeof(scap_evt) && parameter_length_entry_size > 0) {
    max_length_entries_in_buffer =
        static_cast<uint32_t>((size - sizeof(scap_evt)) / parameter_length_entry_size);
  }

  // nparams must not exceed the event type's schema or the space in our buffer.
  event->nparams = std::min(event->nparams,
                            std::min<uint32_t>(event_info->nparams,
                                               max_length_entries_in_buffer));
  if (event->nparams == 0) {
    return 0;
  }

  // Decode parameter start/size for each param; this is the code we're fuzzing.
  std::vector<scap_sized_buffer> decoded_parameters(event->nparams);
  const uint32_t decoded_parameter_count =
      scap_event_decode_params(event, decoded_parameters.data());

  // Walk decoded params and dereference decoder-returned parameter pointers so
  // the fuzzer can exercise the addresses/sizes produced by decode logic.
  const uint32_t parameters_to_visit =
      std::min(decoded_parameter_count,
               static_cast<uint32_t>(decoded_parameters.size()));
  const uint8_t* const buffer_begin = event_bytes.data();
  const uint8_t* const buffer_end = buffer_begin + size;

  volatile uint8_t sink = 0;
  for (uint32_t i = 0; i < parameters_to_visit; ++i) {
    const uint8_t* const parameter_bytes =
        reinterpret_cast<const uint8_t*>(decoded_parameters[i].buf);
    const size_t parameter_size = decoded_parameters[i].size;

    if (parameter_bytes == nullptr || parameter_size == 0) {
      continue;
    }

    // Keep reads inside this input buffer when touching first/last bytes.
    if (parameter_bytes < buffer_begin || parameter_bytes >= buffer_end) {
      continue;
    }
    const size_t remaining = static_cast<size_t>(buffer_end - parameter_bytes);
    if (parameter_size > remaining) {
      continue;
    }

    sink ^= parameter_bytes[0];
    sink ^= parameter_bytes[parameter_size - 1];
  }
  (void)sink;

  return 0;  // 0 = input was handled (libFuzzer convention).
}

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <vector>

#include <driver/ppm_events_public.h>
#include <libscap/scap.h>

// `data`/`size` is one libFuzzer input.
// We treat it as one `scap_evt` record:
// header + parameter-length table + parameter payload bytes.
// A "parameter" is one event argument/field. We:
// 1) decode parameter boundaries, and
// 2) read payload bytes for decoded parameters (with bounds checks).
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // Need at least an event header.
  if (size < sizeof(scap_evt)) {
    return 0;
  }

  // Keep each run bounded.
  const size_t max_input_size = (1U << 16);
  if (size > max_input_size) {
    size = max_input_size;
  }

  // Copy input so we can normalize header fields.
  std::vector<uint8_t> event_bytes(data, data + size);
  auto* event = reinterpret_cast<scap_evt*>(event_bytes.data());

  // Normalize header fields.
  event->len = static_cast<uint32_t>(size);
  event->type = static_cast<uint16_t>(event->type % PPM_EVENT_MAX);

  // Some events use 2-byte parameter lengths, others use 4-byte lengths.
  const ppm_event_info* event_info = scap_event_getinfo(event);
  const uint32_t parameter_length_entry_size =
      (event_info->flags & EF_LARGE_PAYLOAD) ? sizeof(uint32_t) : sizeof(uint16_t);

  // Compute how many length entries fit in this input.
  uint32_t max_length_entries_in_buffer = 0;
  if (size > sizeof(scap_evt) && parameter_length_entry_size > 0) {
    max_length_entries_in_buffer =
        static_cast<uint32_t>((size - sizeof(scap_evt)) / parameter_length_entry_size);
  }

  // Clamp nparams to schema + buffer limits.
  event->nparams = std::min(event->nparams,
                            std::min<uint32_t>(event_info->nparams,
                                               max_length_entries_in_buffer));
  if (event->nparams == 0) {
    return 0;
  }

  // Decode parameter pointers and sizes.
  std::vector<scap_sized_buffer> decoded_parameters(event->nparams);
  const uint32_t decoded_parameter_count =
      scap_event_decode_params(event, decoded_parameters.data());

  // Touch payload bytes for decoded parameters.
  const uint32_t parameters_to_visit =
      std::min(decoded_parameter_count,
               static_cast<uint32_t>(decoded_parameters.size()));

  size_t payload_cursor =
      sizeof(scap_evt) +
      static_cast<size_t>(parameter_length_entry_size) * event->nparams;

  volatile uint8_t sink = 0;
  for (uint32_t i = 0; i < parameters_to_visit; ++i) {
    const size_t parameter_size = decoded_parameters[i].size;

    if (parameter_size == 0) {
      continue;
    }

    // Stop if this parameter would run past input bounds.
    if (payload_cursor > size || parameter_size > size - payload_cursor) {
      break;
    }

    const uint8_t* parameter_bytes = event_bytes.data() + payload_cursor;
    sink ^= parameter_bytes[0];
    sink ^= parameter_bytes[parameter_size - 1];

    payload_cursor += parameter_size;
  }
  (void)sink;

  return 0;
}

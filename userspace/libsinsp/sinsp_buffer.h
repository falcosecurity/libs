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

#pragma once

#include <libscap/scap.h>
#include <libsinsp/event.h>
#include <libsinsp/sinsp_parser_verdict.h>

#include <cstdint>
#include <functional>
#include <memory>
#include <string>

class sinsp;
class sinsp_parser;

/*!
  \brief Handle of a sinsp buffer.

  A sinsp buffer is the unit of event reading and parsing state of an inspector. Every
  inspector owns the default buffer, identified by `SINSP_INVALID_BUFFER_HANDLE` (the name of #2853:
  the "invalid" handle selects the default buffer), which reads the single, merged event stream
  (`scap_next()`). Other buffers are obtained with `sinsp::reserve_buffer_handle()` and read the
  matching libscap buffer (`scap_buffer_next()`).
*/
using sinsp_buffer_t = uint16_t;

constexpr sinsp_buffer_t SINSP_INVALID_BUFFER_HANDLE = 0;

/*!
  \brief The event and parsing state that belongs to a single reader of events.

  Everything that `sinsp::next()` writes while it fetches and parses one event, and that is
  only meaningful until the next call, lives here: the event storage returned to the caller, the
  parser with its scratch event, the verdict of the last parsed event, the event kept aside by
  the fetch logic, the state replayed after the initial state events and the last error.

  The state that describes the observed system (thread table, user and group manager, plugins,
  statistics, event counter) is not part of a buffer and stays in `sinsp`.

  A buffer is accessed by one reader at a time. No synchronization is provided.
*/
class sinsp_buffer {
public:
	// Creates the parser of the buffer. It receives the scratch event owned by the buffer.
	using parser_factory = std::function<std::unique_ptr<sinsp_parser>(sinsp_evt& tmp_evt)>;

	sinsp_buffer(sinsp* inspector, scap_buffer_t scap_buffer_h, const parser_factory& make_parser);
	~sinsp_buffer();

	sinsp_buffer(const sinsp_buffer&) = delete;
	sinsp_buffer& operator=(const sinsp_buffer&) = delete;

	// The default buffer reads the merged event stream.
	bool is_default() const { return m_scap_buffer_h == SCAP_INVALID_BUFFER_HANDLE; }

private:
	friend class sinsp;

	const scap_buffer_t m_scap_buffer_h;

	// The event handed to the caller of `sinsp::next()`.
	sinsp_evt m_evt;
	std::string m_lasterr;

	// Temporary storage for the parser event, to avoid memory allocation.
	sinsp_evt m_parser_tmp_evt;
	// The parsing engine.
	std::unique_ptr<sinsp_parser> m_parser;
	sinsp_parser_verdict m_parser_verdict;

	// Holds an event dequeued from the async events queue (default buffer only).
	std::unique_ptr<sinsp_evt> m_async_evt;

	// Temporary storage for the libscap event: it keeps the event fetched from libscap while
	// qualified events from the async events queue are being processed.
	class delayed_scap_evt {
	public:
		explicit delayed_scap_evt(const scap_buffer_t& scap_buffer_h):
		        m_scap_buffer_h{scap_buffer_h} {}

		inline auto next(scap_t* h) {
			int32_t res;
			if(m_scap_buffer_h == SCAP_INVALID_BUFFER_HANDLE) {
				res = scap_next(h, &m_pevt, &m_cpuid, &m_dump_flags);
			} else {
				res = scap_buffer_next(h, m_scap_buffer_h, &m_pevt, &m_dump_flags);
				m_cpuid = 0;
			}
			if(res != SCAP_SUCCESS) {
				clear();
			}
			return res;
		}
		inline void move(sinsp_evt* evt) {
			evt->set_scap_evt(m_pevt);
			evt->set_cpuid(m_cpuid);
			evt->set_dump_flags(m_dump_flags);
			clear();
		}
		inline bool empty() const { return m_pevt == nullptr; }
		inline void clear() {
			m_pevt = nullptr;
			m_cpuid = 0;
			m_dump_flags = 0;
		}

		const scap_buffer_t& m_scap_buffer_h;
		scap_evt* m_pevt{nullptr};
		uint16_t m_cpuid{0};
		uint32_t m_dump_flags{0};
	};
	delayed_scap_evt m_delayed_scap_evt;

	// An instance of scap_evt to be used during the next call to sinsp::next().
	// If non-null, sinsp::next will use this pointer instead of invoking scap_next().
	// After using this event, sinsp::next() will set this back to nullptr.
	// This is used internally during the state initialization phase (default buffer only).
	scap_evt* m_replay_scap_evt{nullptr};
	// Related to m_replay_scap_evt: the cpuid and flags of the replayed scap event.
	uint16_t m_replay_scap_cpuid{0};
	uint32_t m_replay_scap_flags{0};
};

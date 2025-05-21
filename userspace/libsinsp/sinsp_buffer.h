// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2025 The Falco Authors.

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

typedef uint16_t sinsp_buffer_t;
class sinsp_parser;
class sinsp_parser_shared_params;

extern sinsp_buffer_t SINSP_INVALID_BUFFER_HANDLE;

#define IS_DEFAULT_SINSP_BUFFER(buffer) (buffer.m_sinsp_buffer_h == SINSP_INVALID_BUFFER_HANDLE)

/**
 * @brief Buffer to use in multi-thread mode.
 */
class sinsp_buffer {
	const sinsp_buffer_t m_sinsp_buffer_h;
	const scap_buffer_t m_scap_buffer_h;

	friend sinsp;

	/* ========================= TAKEN FROM SINSP ========================= */
	// TODO: m_async_events_queue

	sinsp_evt m_evt;

	std::string m_lasterr;

	// temporary storage for the parser event to avoid memory allocation
	sinsp_evt m_parser_tmp_evt;
	// the parsing engine
	std::unique_ptr<sinsp_parser> m_parser;

	sinsp_parser_verdict m_parser_verdict;

	// TODO: compare_evt_timestamps is copied from sinsp... Avoid duplication
	// regulates the logic behind event timestamp ordering.
	// returns true if left "comes first" than right, and false otherwise.
	// UINT64_MAX stands for max time priority -- as early as possible.
	static inline bool compare_evt_timestamps(uint64_t left, uint64_t right) {
		return left == static_cast<uint64_t>(-1) || left <= right;
	}
	// predicate struct for checking the head of the async events queue.
	// keeping a struct in the internal state makes sure that we don't do
	// any extra allocation by creating a lambda and its closure
	struct {
		uint64_t ts{0};

		bool operator()(const sinsp_evt& evt) const {
			return compare_evt_timestamps(evt.get_scap_evt()->ts, ts);
		};
	} m_async_events_checker;

	using sinsp_evt_ptr = std::unique_ptr<sinsp_evt>;
	// Holds an event dequeued from the above queue
	sinsp_evt_ptr m_async_evt;

	// temp storage for scap_next
	// stores top scap_evt while qualified events from m_async_events_queue are being processed
	class delayed_scap_evt {
		sinsp_buffer& m_buffer;

	public:
		explicit delayed_scap_evt(sinsp_buffer& buffer): m_buffer{buffer} {}
		inline auto next(scap_t* h) {
			const auto scap_buffer_h = m_buffer.m_scap_buffer_h;
			int32_t res;
			if(scap_buffer_h == SCAP_INVALID_BUFFER_HANDLE) {
				res = scap_next(h, &m_pevt, &m_cpuid, &m_dump_flags);
			} else {
				res = scap_buffer_next(h, scap_buffer_h, &m_pevt, &m_dump_flags);
				m_cpuid = 0;  // TODO: what should we set here?
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
		scap_evt* m_pevt{nullptr};
		uint16_t m_cpuid{0};
		uint32_t m_dump_flags{0};  // TODO: original field was not initialized, verify that this
		                           // initialization does not cause problems
	};

	delayed_scap_evt m_delayed_scap_evt;

	// used only
	uint64_t m_next_flush_time_ns;
	uint64_t m_last_procrequest_tod;

	// An instance of scap_evt to be used during the next call to sinsp::next().
	// If non-null, sinsp::next will use this pointer instead of invoking scap_next().
	// After using this event, sinsp::next() will set this back to NULL.
	// This is used internally during the state initialization phase.
	scap_evt* m_replay_scap_evt;
	//
	// This is related to m_replay_scap_evt, and is used to store the additional cpuid
	// information of the replayed scap event.
	uint16_t m_replay_scap_cpuid;
	uint32_t m_replay_scap_flags;

public:
	sinsp_buffer(const sinsp_buffer_t& sinsp_buffer_h,
	             const scap_buffer_t& scap_buffer_h,
	             sinsp* inspector,
	             const std::shared_ptr<sinsp_parser_shared_params>& parser_ctor_params);
};

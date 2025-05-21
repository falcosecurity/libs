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

#include <libsinsp/sinsp_buffer.h>
#include <libsinsp/parsers.h>

sinsp_buffer::sinsp_buffer(const sinsp_buffer_t& sinsp_buffer_h,
                           const scap_buffer_t& scap_buffer_h,
                           sinsp* inspector,
                           const std::shared_ptr<sinsp_parser_shared_params>& parser_shared_params):
        m_sinsp_buffer_h{sinsp_buffer_h},
        m_scap_buffer_h{scap_buffer_h},
        m_evt{inspector},
        m_lasterr{},
        m_parser_tmp_evt{inspector},
        m_parser{std::make_unique<sinsp_parser>(parser_shared_params, m_parser_tmp_evt)},
        m_parser_verdict{},
        m_async_events_checker{},
        m_async_evt{nullptr},
        m_delayed_scap_evt{*this},
        m_next_flush_time_ns{0},    // TODO: determine if this is correctly initialized
        m_last_procrequest_tod{0},  // TODO: determine if this is correctly initialized
        m_replay_scap_evt{nullptr},
        m_replay_scap_cpuid{0},  // TODO: determine if this is correctly initialized
        m_replay_scap_flags{0}   // TODO: determine if this is correctly initialized
{}

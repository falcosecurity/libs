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

#include <libsinsp/sinsp_buffer.h>
#include <libsinsp/parsers.h>

sinsp_buffer::sinsp_buffer(sinsp* inspector,
                           const scap_buffer_t scap_buffer_h,
                           const parser_factory& make_parser):
        m_scap_buffer_h{scap_buffer_h},
        m_evt{inspector},
        m_parser_tmp_evt{inspector},
        m_delayed_scap_evt{m_scap_buffer_h} {
	m_parser = make_parser(m_parser_tmp_evt);
}

sinsp_buffer::~sinsp_buffer() = default;

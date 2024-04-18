// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.
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

#include <libsinsp/logger.h>
#include <libsinsp/plugin.h>

#include <memory>
#include <string>
#include <vector>

/**
 * @brief Extension of the sinsp parsers that processes an event with
 * a plugin that has event parsing capability. The parser is guaranteed to
 * process all the event of a given capture, once and only once.
 */
class sinsp_plugin_parser
{
public:
	sinsp_plugin_parser(const std::shared_ptr<sinsp_plugin>& p):
			m_plugin(p),
			m_compatible_plugin_sources_bitmap()
	{
		if (!(p->caps() & CAP_PARSING))
		{
			throw sinsp_exception("can't create a sinsp_plugin_parser with a plugin that has no event parsing capability");
		}
	}

    virtual ~sinsp_plugin_parser() = default;
    sinsp_plugin_parser(sinsp_plugin_parser&&) = default;
    sinsp_plugin_parser& operator = (sinsp_plugin_parser&&) = default;
    sinsp_plugin_parser(const sinsp_plugin_parser& s) = default;
    sinsp_plugin_parser& operator = (const sinsp_plugin_parser& s) = default;

	inline bool process_event(sinsp_evt* evt, const std::vector<std::string>& evt_sources)
	{
		// reject the event if it comes from an unknown event source
        if (evt->get_source_idx() == sinsp_no_event_source_idx)
        {
            return false;
        }

        // reject the event if its type is not compatible with the plugin
        if (!m_plugin->parse_event_codes().contains((ppm_event_code) evt->get_type()))
        {
            return false;
        }

        // lazily populate the event source compatibility bitmap
        while (m_compatible_plugin_sources_bitmap.size() <= evt->get_source_idx())
        {
            auto src_idx = m_compatible_plugin_sources_bitmap.size();
            m_compatible_plugin_sources_bitmap.push_back(false);
            ASSERT(src_idx < evt_sources.size());
            const auto& source = evt_sources[src_idx];
            auto compatible = sinsp_plugin::is_source_compatible(m_plugin->parse_event_sources(), source);
            m_compatible_plugin_sources_bitmap[src_idx] = compatible;
        }

        // reject the event if its event source is not compatible with the plugin
        if (!m_compatible_plugin_sources_bitmap[evt->get_source_idx()])
        {
            return false;
        }

		return m_plugin->parse_event(evt);
	}

	inline const std::shared_ptr<sinsp_plugin>& plugin() const
	{
		return m_plugin;
	}

private:
    std::shared_ptr<sinsp_plugin> m_plugin;
	std::vector<bool> m_compatible_plugin_sources_bitmap;
};

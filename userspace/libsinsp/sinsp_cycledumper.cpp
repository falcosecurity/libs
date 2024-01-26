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

#include <libsinsp/sinsp_cycledumper.h>
#include <iostream>


sinsp_cycledumper::sinsp_cycledumper(sinsp* inspector, const std::string& base_filename,
                    const int& rollover_mb, const int& duration_seconds,
                    const int& file_limit, const unsigned long& event_limit,
                    const bool& compress):
	m_last_time(0),
	m_file_count_total(0),
	m_file_index(0),
	m_has_started(false),
	m_event_count(0L),
	m_past_names(NULL),
	m_limit_format("")
{
	m_base_filename = base_filename;
	m_rollover_mb = rollover_mb * 1000000L;
	m_duration_seconds = duration_seconds;
	m_file_limit = file_limit;
	m_event_limit = event_limit;
    m_inspector = inspector;
    m_compress  = compress;

	if(duration_seconds > 0 && file_limit > 0)
	{
		m_past_names = new std::string[file_limit];

		for(int32_t j = 0; j < file_limit; j++)
		{
			m_past_names[j] = "";
		}
	}
}

sinsp_cycledumper::~sinsp_cycledumper()
{
	if(m_dumper != nullptr)
	{
		m_dumper->close();
		m_dumper.reset();
	}

	if(m_past_names != nullptr)
	{
		delete[] m_past_names;
	}
}

void sinsp_cycledumper::dump(sinsp_evt* evt)
{
    if(is_new_file_needed(evt))
	{
		autodump_next_file();
    }
    m_dumper->dump(evt);
}

void sinsp_cycledumper::close()
{
	autodump_stop();
}

void sinsp_cycledumper::set_callbacks(std::vector<callback> open_cbs,
									  std::vector<callback> close_cbs)
{
	m_open_file_callbacks = open_cbs;
	m_close_file_callbacks = close_cbs;
}

void sinsp_cycledumper::autodump_next_file()
{
	autodump_stop();
	autodump_start(m_current_filename);
}

void sinsp_cycledumper::autodump_stop()
{
	if(!m_inspector)
	{
		throw sinsp_exception("inspector not opened yet");
	}

	if(m_dumper)
	{
		m_dumper->close();
		m_dumper.reset();
	}

	m_inspector->m_is_dumping = false;

	std::for_each(m_close_file_callbacks.begin(), m_close_file_callbacks.end(), std::ref(*this));
}

void sinsp_cycledumper::autodump_start(const std::string& dump_filename)
{
	if(!m_inspector)
	{
		throw sinsp_exception("inspector not opened yet");
	}

	if(!m_dumper)
	{
		m_dumper = std::make_unique<sinsp_dumper>();
	}

	std::for_each(m_open_file_callbacks.begin(), m_open_file_callbacks.end(), std::ref(*this));

	m_dumper->open(m_inspector, dump_filename.c_str(),
                   m_compress ? SCAP_COMPRESSION_GZIP : SCAP_COMPRESSION_NONE);

	m_inspector->m_is_dumping = true;
}

void sinsp_cycledumper::next_file()
{
	if (m_file_limit > 0 && m_file_index >= m_file_limit)
	{
		m_file_index = 0;
	}


	if(m_duration_seconds > 0)
	{
		// if the user has specified a format then use it
		if(m_base_filename.find("%") != std::string::npos)
		{
			const size_t our_size = 4096;
			char filename[our_size];
			const struct tm *our_time = localtime(&m_last_time);
			if(our_time == nullptr)
			{
				throw sinsp_exception("cannot get localtime in cycle_writer::next_file");
			}

			if(!strftime(filename, our_size, m_base_filename.c_str(), our_time))
			{
				throw sinsp_exception("filename too long!");
			}

			if(m_file_limit > 0)
			{
				if(m_past_names[m_file_index] != "")
				{
					remove(m_past_names[m_file_index].c_str());
				}

				m_past_names[m_file_index] = std::string(filename);
			}

			m_current_filename = filename;
		}
		else	// if no format is provided, then use a counter
		{
			m_current_filename = m_base_filename + std::to_string(m_file_index);
		}
	}
	else
	{
		m_current_filename = m_base_filename;
	}

	if(m_rollover_mb > 0)
	{

		if(m_limit_format.empty())
		{
			int digit_count = 0;
			int our_file_limit = m_file_limit;

			while(our_file_limit > 0)
			{
				digit_count++;
				our_file_limit /= 10;
			}

			std::stringstream ss;
			ss << "%0" << digit_count << "d";
			m_limit_format = ss.str();
		}

		char index[22];

		snprintf(index, sizeof(index), m_limit_format.c_str(), m_file_index);

		m_current_filename += index;
	}

	if(m_event_limit > 0)
	{
		m_current_filename = m_base_filename + std::to_string(m_file_index);
	}

	m_file_count_total++;
	m_file_index++;
}

bool sinsp_cycledumper::is_new_file_needed(sinsp_evt* evt)
{
	m_event_count++;

	if(m_has_started == false)
	{
		m_has_started = true;

        if(m_duration_seconds > 0)
        {
            // timer setup
            m_last_time = evt->get_ts() / ONE_SECOND_IN_NS; // 10^(-9) because it's nanoseconds
        }

        if(!m_inspector->is_live())
        {
            m_last_time = time(NULL);
        }
        next_file();
		return true;
	}

	if(m_duration_seconds > 0)
	{
		if((int)difftime(evt->get_ts() / ONE_SECOND_IN_NS, m_last_time) >= m_duration_seconds)
		{
			m_last_time = evt->get_ts() / ONE_SECOND_IN_NS;
			m_last_reason = "Maximum Time Reached";
			next_file();
			return true;
		}
	}

	if(m_rollover_mb > 0 && m_dumper->written_bytes() > (uint64_t)m_rollover_mb)
	{
		m_last_reason = "Maximum File Size Reached";
		next_file();
		return true;
	}

	// Event limit
	if(m_event_limit > 0 && m_event_count >= m_event_limit)
	{
		m_event_count = 0L;
		m_last_reason = "Maximum Event Number Reached";
		next_file();
		return true;
	}

	return false;
}

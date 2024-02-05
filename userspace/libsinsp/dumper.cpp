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

#include <libsinsp/sinsp.h>
#include <libsinsp/sinsp_int.h>
#include <libscap/scap.h>
#include <libsinsp/dumper.h>

sinsp_dumper::sinsp_dumper()
{
	m_dumper = NULL;
	m_target_memory_buffer = NULL;
	m_target_memory_buffer_size = 0;
	m_nevts = 0;
}

sinsp_dumper::sinsp_dumper(uint8_t* target_memory_buffer, uint64_t target_memory_buffer_size)
{
	m_dumper = NULL;
	m_target_memory_buffer = target_memory_buffer;
	m_target_memory_buffer_size = target_memory_buffer_size;
}

sinsp_dumper::~sinsp_dumper()
{
	if(m_dumper != NULL)
	{
		scap_dump_close(m_dumper);
	}
}

void sinsp_dumper::open(sinsp* inspector, const std::string& filename, bool compress)
{
	char error[SCAP_LASTERR_SIZE];
	if(inspector->get_scap_handle() == NULL)
	{
		throw sinsp_exception("can't start event dump, inspector not opened yet");
	}

	if(m_target_memory_buffer)
	{
		m_dumper = scap_memory_dump_open(inspector->get_scap_platform(), m_target_memory_buffer, m_target_memory_buffer_size, error);
	}
	else
	{
		auto compress_mode = compress ? SCAP_COMPRESSION_GZIP : SCAP_COMPRESSION_NONE;
		m_dumper = scap_dump_open(inspector->get_scap_platform(), filename.c_str(), compress_mode, error);
	}

	if(m_dumper == nullptr)
	{
		throw sinsp_exception(error);
	}

	inspector->m_thread_manager->dump_threads_to_file(m_dumper);
	inspector->m_container_manager.dump_containers(*this);
	inspector->m_usergroup_manager.dump_users_groups(*this);

	m_nevts = 0;
}

void sinsp_dumper::fdopen(sinsp* inspector, int fd, bool compress)
{
	char error[SCAP_LASTERR_SIZE];
	if(inspector->get_scap_handle() == NULL)
	{
		throw sinsp_exception("can't start event dump, inspector not opened yet");
	}

	auto compress_mode = compress ? SCAP_COMPRESSION_GZIP : SCAP_COMPRESSION_NONE;
	m_dumper = scap_dump_open_fd(inspector->get_scap_platform(), fd, compress_mode, true, error);

	if(m_dumper == nullptr)
	{
		throw sinsp_exception(error);
	}

	inspector->m_thread_manager->dump_threads_to_file(m_dumper);
	inspector->m_container_manager.dump_containers(*this);
	inspector->m_usergroup_manager.dump_users_groups(*this);

	m_nevts = 0;
}

void sinsp_dumper::close()
{
	if(m_dumper != NULL)
	{
		scap_dump_close(m_dumper);
		m_dumper = NULL;
	}
}

bool sinsp_dumper::is_open() const
{
	return (m_dumper != NULL);
}

bool sinsp_dumper::written_events() const
{
	return m_nevts;
}

void sinsp_dumper::dump(sinsp_evt* evt)
{
	if(m_dumper == NULL)
	{
		throw sinsp_exception("dumper not opened yet");
	}

	scap_evt* pdevt = evt->get_scap_evt();
	bool do_drop = false;
	scap_dump_flags dflags;

	dflags = evt->get_dump_flags(&do_drop);
	if(do_drop)
	{
		return;
	}

	int32_t res = scap_dump(m_dumper, pdevt, evt->get_cpuid(), dflags);

	if(res != SCAP_SUCCESS)
	{
		throw sinsp_exception(scap_dump_getlasterr(m_dumper));
	}

	m_nevts++;
}

uint64_t sinsp_dumper::written_bytes() const
{
	if(m_dumper == NULL)
	{
		return 0;
	}

	int64_t written_bytes = scap_dump_get_offset(m_dumper);
	if(written_bytes == -1)
	{
		throw sinsp_exception("error getting offset");
	}

	return written_bytes;
}

uint64_t sinsp_dumper::next_write_position() const
{
	if(m_dumper == NULL)
	{
		return 0;
	}

	int64_t position = scap_dump_ftell(m_dumper);
	if(position == -1)
	{
		throw sinsp_exception("error getting offset");
	}

	return position;
}

void sinsp_dumper::flush()
{
	if(m_dumper == NULL)
	{
		throw sinsp_exception("dumper not opened yet");
	}

	scap_dump_flush(m_dumper);
}

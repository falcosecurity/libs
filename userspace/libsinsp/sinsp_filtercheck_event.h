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

#include <libsinsp/sinsp_filtercheck.h>
#include <libsinsp/sinsp_filtercheck_reference.h>

class sinsp_filter_check_event : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_LATENCY = 0,
		TYPE_LATENCY_S = 1,
		TYPE_LATENCY_NS = 2,
		TYPE_LATENCY_QUANTIZED = 3,
		TYPE_LATENCY_HUMAN = 4,
		TYPE_DELTA = 5,
		TYPE_DELTA_S = 6,
		TYPE_DELTA_NS = 7,
		TYPE_RUNTIME_TIME_OUTPUT_FORMAT = 8,
		TYPE_DIR = 9,
		TYPE_TYPE = 10,
		TYPE_TYPE_IS = 11,
		TYPE_SYSCALL_TYPE = 12,
		TYPE_CATEGORY = 13,
		TYPE_CPU = 14,
		TYPE_ARGS = 15,
		TYPE_ARGSTR = 16,
		TYPE_ARGRAW = 17,
		TYPE_INFO = 18,
		TYPE_BUFFER = 19,
		TYPE_BUFLEN = 20,
		TYPE_RESSTR = 21,
		TYPE_RESRAW = 22,
		TYPE_FAILED = 23,
		TYPE_ISIO = 24,
		TYPE_ISIO_READ = 25,
		TYPE_ISIO_WRITE = 26,
		TYPE_IODIR = 27,
		TYPE_ISWAIT = 28,
		TYPE_WAIT_LATENCY = 29,
		TYPE_ISSYSLOG = 30,
		TYPE_COUNT = 31,
		TYPE_COUNT_ERROR = 32,
		TYPE_COUNT_ERROR_FILE = 33,
		TYPE_COUNT_ERROR_NET = 34,
		TYPE_COUNT_ERROR_MEMORY = 35,
		TYPE_COUNT_ERROR_OTHER = 36,
		TYPE_COUNT_EXIT = 37,
		TYPE_COUNT_PROCINFO = 38,
		TYPE_COUNT_THREADINFO = 39,
		TYPE_AROUND = 40,
		TYPE_ABSPATH = 41,
		TYPE_BUFLEN_IN = 42,
		TYPE_BUFLEN_OUT = 43,
		TYPE_BUFLEN_FILE = 44,
		TYPE_BUFLEN_FILE_IN = 45,
		TYPE_BUFLEN_FILE_OUT = 46,
		TYPE_BUFLEN_NET = 47,
		TYPE_BUFLEN_NET_IN = 48,
		TYPE_BUFLEN_NET_OUT = 49,
		TYPE_ISOPEN_READ = 50,
		TYPE_ISOPEN_WRITE = 51,
		TYPE_INFRA_DOCKER_NAME = 52,
		TYPE_INFRA_DOCKER_CONTAINER_ID = 53,
		TYPE_INFRA_DOCKER_CONTAINER_NAME = 54,
		TYPE_INFRA_DOCKER_CONTAINER_IMAGE = 55,
		TYPE_ISOPEN_EXEC = 56,
		TYPE_ISOPEN_CREATE = 57,
	};

	sinsp_filter_check_event();
	virtual ~sinsp_filter_check_event() = default;

	std::unique_ptr<sinsp_filter_check> allocate_new() override;
	int32_t parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering) override;
	size_t parse_filter_value(const char* str, uint32_t len, uint8_t* storage, uint32_t storage_len) override;
	const filtercheck_field_info* get_field_info() const override;

protected:
	Json::Value extract_as_js(sinsp_evt*, OUT uint32_t* len) override;
	virtual uint8_t* extract(sinsp_evt*, OUT uint32_t* len, bool sanitize_strings = true) override;
	virtual bool compare_nocache(sinsp_evt*) override;

private:
	void validate_filter_value(const char* str, uint32_t len);
	int32_t extract_arg(std::string fldname, std::string val, OUT const struct ppm_param_info** parinfo);
	int32_t extract_type(std::string fldname, std::string val, OUT const struct ppm_param_info** parinfo);
	uint8_t* extract_error_count(sinsp_evt *evt, OUT uint32_t* len);
	uint8_t *extract_abspath(sinsp_evt *evt, OUT uint32_t *len);
	inline uint8_t* extract_buflen(sinsp_evt *evt, OUT uint32_t* len);

	uint64_t m_u64val;
	int64_t m_s64val;
	uint64_t m_tsdelta;
	uint16_t m_u16val;
	uint32_t m_u32val;
	std::string m_strstorage;
	std::string m_argname;
	int32_t m_argid;
	uint32_t m_evtid;
	uint32_t m_evtid1;
	const ppm_param_info* m_arginfo;

	//
	// Note: this copy of the field is used by some fields, like TYPE_ARGS and
	// TYPE_RESARG, that need to do on the fly type customization
	//
	filtercheck_field_info m_customfield;
	bool m_is_compare;
	std::unique_ptr<sinsp_filter_check_reference> m_converter;
};

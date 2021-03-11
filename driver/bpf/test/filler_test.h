/*
Copyright (C) 2021 The Falco Authors.

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

#ifndef _TEST_FILLER_TEST_H
#define _TEST_FILLER_TEST_H

extern "C"
{
#include "probe_loader.h"
}

#include <string>

class filler_test
{
public:
	explicit filler_test(ppm_event_type event_type);
	virtual ~filler_test();

public:
	int do_test(unsigned long retval,
		    unsigned long arg0 = 0,
		    unsigned long arg1 = 0,
		    unsigned long arg2 = 0,
		    unsigned long arg3 = 0,
		    unsigned long arg4 = 0,
		    unsigned long arg5 = 0);
	unsigned long get_argument(void* to, uint32_t off, unsigned long n);
	unsigned long get_argument(uint32_t off);
	unsigned long get_retval();

private:
	std::string m_filler_name{};
	enum ppm_event_type m_event_type;
	char* m_scratch{};
	int m_filler_nparams;
	int m_scratch_header_offset;
};

#endif // _TEST_FILLER_TEST_H

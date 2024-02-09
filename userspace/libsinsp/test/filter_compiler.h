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

#include <libsinsp/filter.h>
#include <libsinsp/event.h>
#include <libsinsp/sinsp_exception.h>
#include <memory>

// passing a NULL out pointer means expecting a failure
static void filter_compile(sinsp_filter **out, std::string filter)
{
	sinsp_filter_check_list flist;
	std::shared_ptr<sinsp_filter_factory> factory(new sinsp_filter_factory(NULL, flist));
	sinsp_filter_compiler compiler(factory, filter);
	try
	{
		auto f = compiler.compile();
		if (!out)
		{
			FAIL() << "Unexpected successful compilation for: " << filter;
		}
		else
		{
			*out = f.release();
		}
	}
	catch(const sinsp_exception& e)
	{
		if (out)
		{
			FAIL() << "Can't compile: " << filter << " -> " << e.what();
		}
	}
}

static void filter_run(sinsp_evt* evt, bool result, std::string filter_str)
{
	sinsp_filter *filter = NULL;
	filter_compile(&filter, filter_str);
	auto f = std::unique_ptr<sinsp_filter>(filter);
	if (f->run(evt) != result)
	{
		FAIL() << filter_str
			<< " -> unexpected '"
			<< (result ? "false" : "true") << "' result";
	}
}


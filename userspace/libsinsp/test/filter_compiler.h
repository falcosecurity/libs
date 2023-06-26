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

#include <gen_filter.h>
#include <filter.h>
#include <event.h>
#include <sinsp_exception.h>
#include <memory>

// passing a NULL out pointer means expecting a failure
static void filter_compile(sinsp_filter **out, std::string filter)
{
	std::shared_ptr<gen_event_filter_factory> factory(new sinsp_filter_factory(NULL));
	sinsp_filter_compiler compiler(factory, filter);
	try
	{
		auto f = compiler.compile();
		if (!out)
		{
			delete f;
			FAIL() << "Unexpected successful compilation for: " << filter;
		}
		else
		{
			*out = f;
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


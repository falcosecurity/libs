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

#include "visitor.h"
#include "cpp_readwrite_visitor.h"

#include <scap.h>

#include <memory>

extern const struct ppm_event_info g_event_info[];

int main(int argc, char** argv)
{
	std::unique_ptr<defs_visitor> v(new cpp_readwrite_defs_visitor());

	v->start_events();
#define PPM_EVENT_X(name, value) v->on_event(PPME_##name, "PPME_"#name, g_event_info[(int) PPME_##name]);
	PPM_EVENT_FIELDS
#undef PPM_EVENT_X
	v->end_events();

	v->start_sc();
#define PPM_SC_X(name, value) v->on_sc(PPM_SC_##name, "PPM_SC_"#name, scap_get_ppm_sc_name(PPM_SC_##name));
	PPM_SC_FIELDS
#undef PPM_SC_X
	v->end_sc();

	return 0;
}

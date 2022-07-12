/*
Copyright (C) 2022 The Falco Authors.

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

#include "state.h"

#include "events_prog_names.h"

#ifdef TEST_HELPERS
/// TODO: move in prog_names.c
const char* pman_get_event_prog_name(int event_type)
{
	return event_prog_names[event_type];
}

const char* pman_get_extra_event_prog_name(int event_type)
{
	return extra_event_prog_names[event_type];
}
#endif
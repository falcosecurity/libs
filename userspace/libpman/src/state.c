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

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "state.h"

struct internal_state g_state;

void pman_print_error(const char* error_message)
{
	if(!error_message)
	{
		fprintf(stderr, "libpman: No specific message available (errno: %d | message: %s)\n", errno, strerror(errno));
	}
	else
	{
		fprintf(stderr, "libpman: %s (errno: %d | message: %s)\n", error_message, errno, strerror(errno));
	}
}
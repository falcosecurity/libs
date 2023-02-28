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

struct internal_state g_state = {};

void pman_print_error(const char* error_message)
{
	if(!error_message)
	{
		return;
	}

	if(errno != 0)
	{
		/*
		 * libbpf uses -ESRCH to indicate that something could not be found,
		 * e.g. vmlinux or btf id. This will be interpreted via strerror as "No
		 * such process" (which was the original meaning of the error code),
		 * and it is extremely confusing. Avoid that by having a special case
		 * for this error code.
		 */
		if (errno == ESRCH)
		{
			fprintf(stderr, "libpman: %s (errno: %d | message: %s)\n",
					error_message, errno, "Object not found");
		}
		else
		{
			fprintf(stderr, "libpman: %s (errno: %d | message: %s)\n",
					error_message, errno, strerror(errno));
		}
	}
	else
	{
		fprintf(stderr, "libpman: %s\n", error_message);
	}
}

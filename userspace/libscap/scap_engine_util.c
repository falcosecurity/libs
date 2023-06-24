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

#include <errno.h>
#include <stdio.h>
#include <time.h>

#include "scap_engine_util.h"
#include "scap_const.h"
#include "strerror.h"

#include "compat/misc.h"

static inline uint64_t timespec_to_nsec(const struct timespec* ts)
{
	return ts->tv_sec * 1000000000 + ts->tv_nsec;
}

int32_t scap_get_precise_boot_time(char* last_err, uint64_t *boot_time)
{
	struct timespec wall_ts, boot_ts;

	if(clock_gettime(CLOCK_BOOTTIME, &boot_ts) < 0)
	{
		return scap_errprintf(last_err, errno, "Failed to get CLOCK_BOOTTIME");
	}

	if(clock_gettime(CLOCK_REALTIME, &wall_ts) < 0)
	{
		return scap_errprintf(last_err, errno, "Failed to get CLOCK_REALTIME");
	}

	*boot_time = timespec_to_nsec(&wall_ts) - timespec_to_nsec(&boot_ts);
	return SCAP_SUCCESS;
}

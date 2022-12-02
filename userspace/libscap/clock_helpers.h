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
#ifndef __CLOCK_HELPERS_H
#define __CLOCK_HELPERS_H

#define SCAP_GET_CUR_TS_MS_CONTEXT_INIT ((uint64_t)0)
#define SCAP_GET_CUR_TS_MS_CONTEXT_ERROR_FLAG ((uint64_t)0x8000000000000000)
#define SCAP_GET_CUR_TS_MS_CONTEXT_PREV_VALUE_MASK ((uint64_t)0x7fffffffffffffff)

#define S_TO_MS(_sec) (((uint64_t)_sec) * (uint64_t)1000)
#define NS_TO_MS(_ns) (((uint64_t)_ns) / ((uint64_t)(1000 * 1000)))

#ifndef __always_inline
#define __always_inline inline
#endif

/**
 * Return monotonically increasing time in ms.
 * Caller initializes context to SCAP_GET_CUR_TS_MS_CONTEXT_INIT,
 * Function uses and updates context, to recognize and handle the
 * following cases:
 * - failed clock_gettime() system call
 * - non-monotonic behavior of CLOCK_MONOTONIC
 * - time values that cannot be represented in uint64_t number of msec
 */
static __always_inline uint64_t scap_get_monotonic_ts_ms(uint64_t* context)
{
	// Record previously reported time; will be 0 for first call.
	uint64_t prev_time = ((*context) & SCAP_GET_CUR_TS_MS_CONTEXT_PREV_VALUE_MASK);

	// If context indicates error already detected, just return the
	// last reported time
	if ((*context) & SCAP_GET_CUR_TS_MS_CONTEXT_ERROR_FLAG)
	{
		return prev_time;
	}

	// Fetch current monotonic time from kernel
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts))
	{
		// System call failed.
		// Set error flag
		*context |= SCAP_GET_CUR_TS_MS_CONTEXT_ERROR_FLAG;

		// Return previously reported time, now frozen
		return prev_time;
	}

	// Form new time
	uint64_t new_time = S_TO_MS(ts.tv_sec) + NS_TO_MS(ts.tv_nsec);

	// Check for overflow or non-monotonic behavior
	if ((new_time & SCAP_GET_CUR_TS_MS_CONTEXT_ERROR_FLAG) ||
	    (new_time < prev_time))
	{
		// System call failed.
		// Set error flag
		*context |= SCAP_GET_CUR_TS_MS_CONTEXT_ERROR_FLAG;

		// Return previously reported time, now frozen
		return prev_time;
	}

	// New time looks OK.
	// Store it into the context, and return it.
	*context = new_time;
	return new_time;
}

#endif /* __CLOCK_HELPERS_H */

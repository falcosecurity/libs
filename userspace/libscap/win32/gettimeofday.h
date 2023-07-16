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

#pragma once

#include <Windows.h>
#include <stdint.h>

static inline uint64_t ft_to_epoch_nsec(FILETIME* ft)
{
	static const uint64_t EPOCH = ((uint64_t) 116444736000000000ULL);
	uint64_t ftl = (((uint64_t)ft->dwHighDateTime) << 32) + ft->dwLowDateTime;
	ftl -= EPOCH;

	uint64_t ts = ftl * 100;
	return ts;
}

static inline uint64_t get_timestamp_ns()
{
	FILETIME ft;
	GetSystemTimePreciseAsFileTime(&ft);

	return ft_to_epoch_nsec(&ft);
}


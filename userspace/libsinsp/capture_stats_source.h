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
#pragma once

#include <libsinsp/sinsp_public.h>
#include <stdint.h>
#include <libsinsp/logger.h>

struct scap_stats;

/**
 * Interface to an object that can provide capture statistics.
 *
 * Note that the intention here is to apply the Interface Segregation
 * Principle (ISP) to class sinsp.  Some clients of sinsp need only the
 * get_capture_stats() API, and this interface exposes only that API.  Do
 * not add additional APIs here.  If some client of sinsp needs a different
 * set of APIs, introduce a new interface.
 */
class SINSP_PUBLIC capture_stats_source
{
public:
	virtual ~capture_stats_source() = default;

	/**
	 * Fill the given structure with statistics about the currently
	 * open capture.
	 *
	 * @note This may not work for a file-based capture source.
	 *
	 * @param[out] stats The capture statistics
	 */
	virtual void get_capture_stats(scap_stats* stats) const = 0;

	/**
	 * Print a log with statistics about the currently
	 * open capture.
	 *
	 * @note This may not work for a file-based capture source.
	 *
	 * @param[in] sev severity used to log
	 */
	virtual void print_capture_stats(sinsp_logger::severity sev) const = 0;

	/**
	 * Get engine statistics (including counters and `bpftool prog show` like stats).
	 *
	 * @return Pointer to a \ref metrics_v2 structure filled with the libscap stats.
	 */
	virtual const struct metrics_v2* get_capture_stats_v2(uint32_t flags, uint32_t* nstats, int32_t* rc) const = 0;
};

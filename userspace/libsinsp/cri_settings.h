// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2025 The Falco Authors.

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

#include <libsinsp/container_info.h>

#include <chrono>
#include <string>

namespace libsinsp {
namespace cri {

using namespace std::chrono_literals;

/**
 * Store the parameters for retrying CRI API calls.
 * The retry behavior is exponential backoff with an initial interval of 250ms
 * and an exponential factor of 2.
 */
struct retry_parameters {
	// The maximum number of retries for CRI API calls used to get container
	// metadata.
	int16_t max_retries = 7;
	// The maximum interval between retries in milliseconds used to cap the
	// exponential backoff.
	std::chrono::milliseconds max_interval_ms = 2s;
	// The maximum time to wait for a successful lookup in milliseconds,
	// regardless of the number of retries.
	std::chrono::seconds global_timeout_s = 30s;
	// The initial delay in milliseconds before the first attempt.
	std::chrono::milliseconds initial_delay_ms = 0ms;
	// Setters applying the values only if they are within the allowed range
	bool set_max_retries(int16_t retries);
	bool set_max_interval_ms(std::chrono::milliseconds interval);
	bool set_global_timeout_s(std::chrono::seconds timeout);
	bool set_initial_delay_ms(std::chrono::milliseconds delay);
	// Move assignement operator that checks the values are within the allowed range
	retry_parameters &operator=(const retry_parameters &other) noexcept;
	// Basic operators
	std::string to_string() const;
	bool operator==(const retry_parameters &other) const;
	bool operator!=(const retry_parameters &other) const;
};

class cri_settings {
public:
	cri_settings();
	~cri_settings();
	static cri_settings &get();

	static const std::vector<std::string> &get_cri_unix_socket_paths() {
		return get().m_cri_unix_socket_paths;
	}

	static void set_cri_unix_socket_paths(const std::vector<std::string> &v) {
		get().m_cri_unix_socket_paths = v;
	}

	static const int64_t &get_cri_timeout() { return get().m_cri_timeout; }

	static void set_cri_timeout(const int64_t &v) { get().m_cri_timeout = v; }

	static const int64_t &get_cri_size_timeout() { return get().m_cri_size_timeout; }

	static void set_cri_size_timeout(const int64_t &v) { get().m_cri_size_timeout = v; }

	/**
	 * Get the retry parameters for CRI API calls used to fetch the container
	 * metadata.
	 *
	 * @return the maximum number of retries
	 */
	static const retry_parameters &get_cri_retry_parameters() {
		return get().m_cri_retry_parameters;
	}

	/**
	 * Set the retry parameters for CRI API calls used to fetch the container
	 * metadata.
	 *
	 * @param v the retry parameters used to determine the retry behavior.
	 * @return true if the parameters were set without changes, false if the
	 * values were out of range and were adjusted.
	 */
	static bool set_cri_retry_parameters(const retry_parameters &v);

	static const sinsp_container_type &get_cri_runtime_type() { return get().m_cri_runtime_type; }

	static void set_cri_runtime_type(const sinsp_container_type &v) {
		get().m_cri_runtime_type = v;
	}

	static const bool &get_cri_extra_queries() { return get().m_cri_extra_queries; }

	static void set_cri_extra_queries(const bool &v) { get().m_cri_extra_queries = v; }

	static void add_cri_unix_socket_path(const std::string &v) {
		get().m_cri_unix_socket_paths.emplace_back(v);
	}

	static void clear_cri_unix_socket_paths() { get().m_cri_unix_socket_paths.clear(); }

private:
	static std::unique_ptr<cri_settings> s_instance;

	cri_settings(const cri_settings &) = delete;
	cri_settings &operator=(const cri_settings &) = delete;

	std::vector<std::string> m_cri_unix_socket_paths;
	int64_t m_cri_timeout;
	int64_t m_cri_size_timeout;
	retry_parameters m_cri_retry_parameters;
	sinsp_container_type m_cri_runtime_type;
	bool m_cri_extra_queries;
};

}  // namespace cri
}  // namespace libsinsp

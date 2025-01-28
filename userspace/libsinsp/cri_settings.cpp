// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

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

#include <libsinsp/cri_settings.h>

#include <string>
#include <sstream>

namespace libsinsp {
namespace cri {

bool retry_parameters::set_max_retries(int16_t retries) {
	static constexpr int16_t min_val = 0;
	if(retries < min_val) {
		return false;
	}
	max_retries = retries;
	return true;
}

bool retry_parameters::set_max_interval_ms(std::chrono::milliseconds interval) {
	static constexpr std::chrono::milliseconds min_val(10), max_val(60000);
	if(interval < min_val || interval > max_val) {
		return false;
	}
	max_interval_ms = std::move(interval);
	return true;
}

bool retry_parameters::set_global_timeout_s(std::chrono::seconds timeout) {
	static constexpr std::chrono::seconds min_val(1), max_val(600);
	if(timeout < min_val || timeout > max_val) {
		return false;
	}
	global_timeout_s = std::move(timeout);
	return true;
}

bool retry_parameters::set_initial_delay_ms(std::chrono::milliseconds delay) {
	static constexpr std::chrono::milliseconds min_val(0), max_val(60000);
	if(delay < min_val || delay > max_val) {
		return false;
	}
	initial_delay_ms = std::move(delay);
	return true;
}

retry_parameters& retry_parameters::operator=(const retry_parameters& other) noexcept {
	assert(other.initial_delay_ms < other.global_timeout_s);
	set_max_retries(other.max_retries);
	set_max_interval_ms(other.max_interval_ms);
	set_global_timeout_s(other.global_timeout_s);
	set_initial_delay_ms(other.initial_delay_ms);
	return *this;
}

std::string retry_parameters::to_string() const {
	std::stringstream ss;
	ss << "max_retries: " << max_retries << ", "
	   << "max_interval_ms: " << max_interval_ms.count() << "ms, "
	   << "global_timeout_s: " << global_timeout_s.count() << "s, "
	   << "initial_delay_ms: " << initial_delay_ms.count() << "ms";
	return ss.str();
}

bool retry_parameters::operator==(const retry_parameters& other) const {
	return max_retries == other.max_retries && max_interval_ms == other.max_interval_ms &&
	       global_timeout_s == other.global_timeout_s && initial_delay_ms == other.initial_delay_ms;
}

bool retry_parameters::operator!=(const retry_parameters& other) const {
	return !(*this == other);
}

cri_settings::cri_settings():
        m_cri_unix_socket_paths(),
        m_cri_timeout(1000),
        m_cri_size_timeout(10000),
        m_cri_retry_parameters(),
        m_cri_runtime_type(CT_CRI),
        m_cri_extra_queries(true) {}

cri_settings::~cri_settings() {}

std::unique_ptr<cri_settings> cri_settings::s_instance = nullptr;

cri_settings& cri_settings::get() {
	if(s_instance == nullptr) {
		s_instance = std::make_unique<cri_settings>();
	}
	return *s_instance;
}

bool cri_settings::set_cri_retry_parameters(const retry_parameters& v) {
	get().m_cri_retry_parameters = v;
	return v == get().m_cri_retry_parameters;
}

}  // namespace cri
}  // namespace libsinsp

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

#if !defined(MINIMAL_BUILD) and \
        !defined(__EMSCRIPTEN__)  // MINIMAL_BUILD and emscripten don't support containers at all
#include <gtest/gtest.h>
#include <libsinsp/cri_settings.h>
#include "../sinsp_with_test_input.h"

TEST_F(sinsp_with_test_input, default_cri_socket_paths) {
	libsinsp::cri::cri_settings& cri_settings = libsinsp::cri::cri_settings::get();

	if(!cri_settings.get_cri_unix_socket_paths().empty()) {
		cri_settings.clear_cri_unix_socket_paths();
	}

	add_default_init_thread();
	open_inspector();

	auto socket_paths = cri_settings.get_cri_unix_socket_paths();

	ASSERT_EQ(socket_paths.size(), 4);
	ASSERT_TRUE("/run/containerd/containerd.sock" == socket_paths[0]);
	ASSERT_TRUE("/run/crio/crio.sock" == socket_paths[1]);
	ASSERT_TRUE("/run/k3s/containerd/containerd.sock" == socket_paths[2]);
	ASSERT_TRUE("/run/host-containerd/containerd.sock" == socket_paths[3]);
}

using namespace std::chrono_literals;

// Test retry parameters
TEST(cri_retry_parameters, set_max_retries) {
	libsinsp::cri::retry_parameters rp;
	ASSERT_TRUE(rp.set_max_retries(0));
	ASSERT_EQ(rp.max_retries, 0);
	ASSERT_FALSE(rp.set_max_retries(-1));
	ASSERT_EQ(rp.max_retries, 0);
	ASSERT_FALSE(rp.set_max_retries(std::numeric_limits<int16_t>::min()));
	ASSERT_EQ(rp.max_retries, 0);
	ASSERT_TRUE(rp.set_max_retries(std::numeric_limits<int16_t>::max()));
	ASSERT_EQ(rp.max_retries, std::numeric_limits<int16_t>::max());
}

TEST(cri_retry_parameters, set_max_interval_ms) {
	libsinsp::cri::retry_parameters rp;
	ASSERT_TRUE(rp.set_max_interval_ms(10ms));
	ASSERT_EQ(rp.max_interval_ms, 10ms);
	ASSERT_FALSE(rp.set_max_interval_ms(9ms));
	ASSERT_EQ(rp.max_interval_ms, 10ms);
	ASSERT_FALSE(rp.set_max_interval_ms(60001ms));
	ASSERT_EQ(rp.max_interval_ms, 10ms);
	ASSERT_TRUE(rp.set_max_interval_ms(60000ms));
	ASSERT_EQ(rp.max_interval_ms, 60000ms);
}

TEST(cri_retry_parameters, set_global_timeout_s) {
	libsinsp::cri::retry_parameters rp;
	ASSERT_TRUE(rp.set_global_timeout_s(1s));
	ASSERT_EQ(rp.global_timeout_s, 1s);
	ASSERT_FALSE(rp.set_global_timeout_s(0s));
	ASSERT_EQ(rp.global_timeout_s, 1s);
	ASSERT_FALSE(rp.set_global_timeout_s(601s));
	ASSERT_EQ(rp.global_timeout_s, 1s);
	ASSERT_TRUE(rp.set_global_timeout_s(600s));
	ASSERT_EQ(rp.global_timeout_s, 600s);
}

TEST(cri_retry_parameters, set_initial_delay_ms) {
	libsinsp::cri::retry_parameters rp;
	ASSERT_TRUE(rp.set_initial_delay_ms(0s));
	ASSERT_EQ(rp.initial_delay_ms, 0ms);
	ASSERT_FALSE(rp.set_initial_delay_ms(-1ms));
	ASSERT_EQ(rp.initial_delay_ms, 0ms);
	ASSERT_FALSE(rp.set_initial_delay_ms(60001ms));
	ASSERT_EQ(rp.initial_delay_ms, 0ms);
	ASSERT_TRUE(rp.set_initial_delay_ms(60000ms));
	ASSERT_EQ(rp.initial_delay_ms, 60000ms);
}

TEST(cri_retry_parameters, to_string) {
	libsinsp::cri::retry_parameters rp;
	rp.set_max_retries(1);
	rp.set_max_interval_ms(10ms);
	rp.set_global_timeout_s(1s);
	rp.set_initial_delay_ms(0ms);
	ASSERT_EQ(rp.to_string(),
	          "max_retries: 1, max_interval_ms: 10ms, global_timeout_s: 1s, initial_delay_ms: 0ms");
}

TEST(cri_retry_parameters, equality) {
	libsinsp::cri::retry_parameters rp1;
	libsinsp::cri::retry_parameters rp2;
	ASSERT_TRUE(rp1 == rp2);
	rp1.set_max_retries(1);
	ASSERT_FALSE(rp1 == rp2);
	rp2.set_max_retries(1);
	ASSERT_TRUE(rp1 == rp2);
	rp1.set_max_interval_ms(std::chrono::milliseconds(100));
	ASSERT_FALSE(rp1 == rp2);
	rp2.set_max_interval_ms(std::chrono::milliseconds(100));
	ASSERT_TRUE(rp1 == rp2);
	rp1.set_global_timeout_s(std::chrono::seconds(1));
	ASSERT_FALSE(rp1 == rp2);
	rp2.set_global_timeout_s(std::chrono::seconds(1));
	ASSERT_TRUE(rp1 == rp2);
	rp1.set_initial_delay_ms(std::chrono::milliseconds(10));
	ASSERT_FALSE(rp1 == rp2);
	rp2.set_initial_delay_ms(std::chrono::milliseconds(10));
	ASSERT_TRUE(rp1 == rp2);
}

TEST(cri_retry_parameters, assignment) {
	libsinsp::cri::retry_parameters rp1{.max_retries = 10,
	                                    .max_interval_ms = 10ms,
	                                    .global_timeout_s = 1s,
	                                    .initial_delay_ms = 0ms};
	libsinsp::cri::retry_parameters rp2;
	rp2 = rp1;
	ASSERT_TRUE(rp1 == rp2);
}

TEST(cri_retry_parameters, failed_assignment) {
	libsinsp::cri::retry_parameters rp1{.max_retries = 10,
	                                    .max_interval_ms = -10ms,
	                                    .global_timeout_s = 1s,
	                                    .initial_delay_ms = 0ms};
	libsinsp::cri::retry_parameters rp2;
	rp2 = rp1;
	ASSERT_TRUE(rp1 != rp2);
}
#endif

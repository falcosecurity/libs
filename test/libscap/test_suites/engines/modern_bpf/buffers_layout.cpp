// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2026 The Falco Authors.

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

#include <gtest/gtest.h>
#include <vector>
#include <libpman.h>

// These tests only exercise the arithmetic and validation of the ring buffers layout: they do not
// load any BPF program, so they do not need any privilege.

namespace {
struct layout {
	int rc;
	uint16_t cpus_for_each_buffer;
	uint32_t n_buffers;
};

layout compute(uint16_t n_cpus, uint16_t cpus_for_each_buffer, uint16_t fixed_buffers_num) {
	layout l{};
	// Poison the outputs to be sure that they are always written on success.
	l.cpus_for_each_buffer = 0xffff;
	l.n_buffers = 0xffffffff;
	l.rc = pman_compute_buffers_layout(n_cpus,
	                                   cpus_for_each_buffer,
	                                   fixed_buffers_num,
	                                   &l.cpus_for_each_buffer,
	                                   &l.n_buffers);
	return l;
}
}  // namespace

TEST(modern_bpf_buffers_layout, one_buffer_per_cpu) {
	const auto l = compute(8, 1, 0);
	ASSERT_EQ(l.rc, 0);
	EXPECT_EQ(l.n_buffers, 8u);
	EXPECT_EQ(l.cpus_for_each_buffer, 1);
}

TEST(modern_bpf_buffers_layout, one_buffer_every_n_cpus_rounds_up) {
	auto l = compute(8, 2, 0);
	ASSERT_EQ(l.rc, 0);
	EXPECT_EQ(l.n_buffers, 4u);
	EXPECT_EQ(l.cpus_for_each_buffer, 2);

	l = compute(7, 2, 0);
	ASSERT_EQ(l.rc, 0);
	EXPECT_EQ(l.n_buffers, 4u);
	EXPECT_EQ(l.cpus_for_each_buffer, 2);
}

TEST(modern_bpf_buffers_layout, zero_cpus_for_each_buffer_means_a_single_buffer) {
	const auto l = compute(8, 0, 0);
	ASSERT_EQ(l.rc, 0);
	EXPECT_EQ(l.n_buffers, 1u);
	EXPECT_EQ(l.cpus_for_each_buffer, 8);
}

TEST(modern_bpf_buffers_layout, cpus_for_each_buffer_greater_than_cpus_fails) {
	EXPECT_EQ(compute(8, 9, 0).rc, -1);
	EXPECT_EQ(compute(8, 8, 0).rc, 0);
}

TEST(modern_bpf_buffers_layout, fixed_buffers_num) {
	for(uint16_t n = 1; n <= 8; n++) {
		const auto l = compute(8, 1, n);
		ASSERT_EQ(l.rc, 0) << "fixed_buffers_num=" << n;
		EXPECT_EQ(l.n_buffers, n);
		EXPECT_EQ(l.cpus_for_each_buffer, 0);
	}
}

TEST(modern_bpf_buffers_layout, fixed_buffers_num_wins_over_cpus_for_each_buffer) {
	// Whatever `cpus_for_each_buffer` is, even an invalid value, `fixed_buffers_num` decides.
	for(const uint16_t cpus_for_each_buffer : {0, 1, 2, 8, 100}) {
		const auto l = compute(8, cpus_for_each_buffer, 3);
		ASSERT_EQ(l.rc, 0) << "cpus_for_each_buffer=" << cpus_for_each_buffer;
		EXPECT_EQ(l.n_buffers, 3u);
	}
}

TEST(modern_bpf_buffers_layout, fixed_buffers_num_greater_than_cpus_fails) {
	EXPECT_EQ(compute(8, 1, 9).rc, -1);
	EXPECT_EQ(compute(8, 1, UINT16_MAX).rc, -1);
	EXPECT_EQ(compute(1, 1, 2).rc, -1);
	EXPECT_EQ(compute(1, 1, 1).rc, 0);
}

TEST(modern_bpf_buffers_layout, failure_does_not_touch_the_outputs) {
	const auto l = compute(8, 1, 9);
	EXPECT_EQ(l.cpus_for_each_buffer, 0xffff);
	EXPECT_EQ(l.n_buffers, 0xffffffffu);
}

TEST(modern_bpf_buffers_layout, cpu_to_buffer_default_mapping_is_unchanged) {
	// one buffer every 3 CPUs: 0 0 0 1 1 1 2 2
	const uint32_t expected[] = {0, 0, 0, 1, 1, 1, 2, 2};
	for(uint16_t cpu = 0; cpu < 8; cpu++) {
		EXPECT_EQ(pman_ringbuf_id_for_cpu(cpu, 3, 0), expected[cpu]) << "cpu=" << cpu;
	}
	// one buffer per CPU
	for(uint16_t cpu = 0; cpu < 8; cpu++) {
		EXPECT_EQ(pman_ringbuf_id_for_cpu(cpu, 1, 0), cpu);
	}
	// a single shared buffer
	for(uint16_t cpu = 0; cpu < 8; cpu++) {
		EXPECT_EQ(pman_ringbuf_id_for_cpu(cpu, 8, 0), 0u);
	}
}

TEST(modern_bpf_buffers_layout, cpu_to_buffer_fixed_mapping_is_round_robin_and_in_range) {
	// 8 CPUs over 3 buffers: 0 1 2 0 1 2 0 1
	const uint32_t expected[] = {0, 1, 2, 0, 1, 2, 0, 1};
	for(uint16_t cpu = 0; cpu < 8; cpu++) {
		EXPECT_EQ(pman_ringbuf_id_for_cpu(cpu, 0, 3), expected[cpu]) << "cpu=" << cpu;
	}

	// Every buffer serves at least one CPU and every CPU gets a valid buffer.
	for(uint16_t n_cpus = 1; n_cpus <= 64; n_cpus++) {
		for(uint16_t fixed = 1; fixed <= n_cpus; fixed++) {
			const auto l = compute(n_cpus, 1, fixed);
			ASSERT_EQ(l.rc, 0);
			std::vector<int> served(l.n_buffers, 0);
			for(uint16_t cpu = 0; cpu < n_cpus; cpu++) {
				const uint32_t id = pman_ringbuf_id_for_cpu(cpu, l.cpus_for_each_buffer, fixed);
				ASSERT_LT(id, l.n_buffers) << "cpus=" << n_cpus << " fixed=" << fixed;
				served[id]++;
			}
			for(const int s : served) {
				ASSERT_GT(s, 0) << "cpus=" << n_cpus << " fixed=" << fixed;
			}
		}
	}
}

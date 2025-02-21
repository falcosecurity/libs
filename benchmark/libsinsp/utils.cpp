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

#include <libsinsp/utils.h>
#include <benchmark/benchmark.h>

static void BM_sinsp_split(benchmark::State& state) {
	for(auto _ : state) {
		std::string str = "hello,world,";
		benchmark::DoNotOptimize(sinsp_split(str, ','));
	}
}
BENCHMARK(BM_sinsp_split);

static void BM_sinsp_concatenate_paths_relative_path(benchmark::State& state) {
	for(auto _ : state) {
		std::string path1 = "/tmp/";
		std::string path2 = "foo/bar";
		benchmark::DoNotOptimize(sinsp_utils::concatenate_paths(path1, path2));
	}
}
BENCHMARK(BM_sinsp_concatenate_paths_relative_path);

static void BM_sinsp_concatenate_paths_empty_path(benchmark::State& state) {
	for(auto _ : state) {
		std::string path1 = "/tmp/";
		std::string path2 = "";
		benchmark::DoNotOptimize(sinsp_utils::concatenate_paths(path1, path2));
	}
}
BENCHMARK(BM_sinsp_concatenate_paths_empty_path);

static void BM_sinsp_concatenate_paths_absolute_path(benchmark::State& state) {
	for(auto _ : state) {
		std::string path1 = "/tmp/";
		std::string path2 = "/foo/bar";
		benchmark::DoNotOptimize(sinsp_utils::concatenate_paths(path1, path2));
	}
}
BENCHMARK(BM_sinsp_concatenate_paths_absolute_path);

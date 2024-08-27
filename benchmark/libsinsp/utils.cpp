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

static void BM_sinsp_split(benchmark::State& state)
{
	std::string str = "hello,world,";
	for(auto _ : state)
	{
		sinsp_split(str, ',');
	}
}
BENCHMARK(BM_sinsp_split);

static void BM_sinsp_concatenate_paths_relative_path2(benchmark::State& state)
{
	std::string path1 = "/tmp/";
	std::string path2 = "foo/bar";
	for(auto _ : state)
	{
		sinsp_utils::concatenate_paths(path1, path2);
	}
}
BENCHMARK(BM_sinsp_concatenate_paths_relative_path2);

static void BM_sinsp_concatenate_paths_empty_path2(benchmark::State& state)
{
	std::string path1 = "/tmp/";
	std::string path2 = "";
	for(auto _ : state)
	{
		sinsp_utils::concatenate_paths(path1, path2);
	}
}
BENCHMARK(BM_sinsp_concatenate_paths_empty_path2);

static void BM_sinsp_concatenate_paths_absolute_path2(benchmark::State& state)
{
	std::string path1 = "/tmp/";
	std::string path2 = "/foo/bar";
	for(auto _ : state)
	{
		sinsp_utils::concatenate_paths(path1, path2);
	}
}
BENCHMARK(BM_sinsp_concatenate_paths_absolute_path2);

static void BM_sinsp_split_container_image(benchmark::State& state)
{
	std::string container_image = "localhost:12345/library/busybox:1.27.2@sha256:da39a3ee5e6b4b0d3255bfef95601890afd80709";
	std::string hostname, port, name, tag, digest;
	for(auto _ : state)
	{
		sinsp_utils::split_container_image(container_image, hostname, port, name, tag, digest);
	}
}
BENCHMARK(BM_sinsp_split_container_image);
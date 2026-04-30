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

// Fast path for short valid ASCII string. No 8-byte aligned block skipping. No replacement needed.
static void BM_sinsp_sanitize_string_fast_path_ascii_short(benchmark::State& state) {
	const std::string str = "/foo/";
	std::string unused_storage;
	for(auto _ : state) {
		benchmark::DoNotOptimize(sanitize_string(str, unused_storage));
	}
}
BENCHMARK(BM_sinsp_sanitize_string_fast_path_ascii_short);

// Fast path for long valid ASCII string. Exercises 8-byte aligned block skipping. No replacement
// needed.
static void BM_sinsp_sanitize_string_fast_path_ascii_long(benchmark::State& state) {
	const std::string str(1024, 'a');
	std::string unused_storage;
	for(auto _ : state) {
		benchmark::DoNotOptimize(sanitize_string(str, unused_storage));
	}
}
BENCHMARK(BM_sinsp_sanitize_string_fast_path_ascii_long);

// Fast path for short valid multibyte UTF-8 string. No 8-byte aligned block skipping. No
// replacement needed.
static void BM_sinsp_sanitize_string_fast_path_multibyte_short(benchmark::State& state) {
	const std::string str{"😀😀"};
	std::string unused_storage;
	for(auto _ : state) {
		benchmark::DoNotOptimize(sanitize_string(str, unused_storage));
	}
}
BENCHMARK(BM_sinsp_sanitize_string_fast_path_multibyte_short);

// Fast path for long valid multibyte UTF-8 string composed of 4-byte sequences. Exercises
// `utf8_seq_len()` for each 4-byte sequence. No replacement needed.
static void BM_sinsp_sanitize_string_fast_path_multibyte_long(benchmark::State& state) {
	const std::string emoji{"😀"};
	std::string str;
	str.reserve(1024 * emoji.size());
	for(int i = 0; i < 1024; i++) {
		str.append(emoji.data(), emoji.size());
	}
	std::string unused_storage;
	for(auto _ : state) {
		benchmark::DoNotOptimize(sanitize_string(str, unused_storage));
	}
}
BENCHMARK(BM_sinsp_sanitize_string_fast_path_multibyte_long);

// Fast path for long valid mixed ASCII and multibyte UTF-8 string. Exercises both 8-byte aligned
// block skipping for ASCII runs and `utf8_seq_len()` for 4-byte sequences. No replacement needed.
static void BM_sinsp_sanitize_string_fast_path_mixed_long(benchmark::State& state) {
	const std::string ascii{"abcdefgh"};
	const std::string emoji{"😀"};
	std::string str;
	str.reserve(128 * (ascii.size() + emoji.size()));
	for(int i = 0; i < 128; i++) {
		str.append(ascii.data(), ascii.size());
		str.append(emoji.data(), emoji.size());
	}
	std::string unused_storage;
	for(auto _ : state) {
		benchmark::DoNotOptimize(sanitize_string(str, unused_storage));
	}
}
BENCHMARK(BM_sinsp_sanitize_string_fast_path_mixed_long);

// Slow path for long valid multibyte UTF-8 composed of 2-byte non-printable characters (C1 control
// characters). Replacement needed for all characters. Storage needs allocation.
static void BM_sinsp_sanitize_string_slow_path_c1_controls_long_alloc(benchmark::State& state) {
	const std::string c1{"\xC2\x80"};
	std::string str;
	str.reserve(512 * c1.size());
	for(int i = 0; i < 512; i++) {
		str.append(c1.data(), c1.size());
	}
	for(auto _ : state) {
		std::string storage;
		benchmark::DoNotOptimize(sanitize_string(str, storage));
	}
}
BENCHMARK(BM_sinsp_sanitize_string_slow_path_c1_controls_long_alloc);

// Slow path for long valid multibyte UTF-8 composed of 2-byte non-printable characters (C1 control
// characters). Replacement needed for all characters. Storage has enough capacity.
static void BM_sinsp_sanitize_string_slow_path_c1_controls_long_noalloc(benchmark::State& state) {
	const std::string c1{"\xC2\x80"};
	std::string str;
	str.reserve(512 * c1.size());
	for(int i = 0; i < 512; i++) {
		str.append(c1.data(), c1.size());
	}
	std::string storage;
	storage.reserve(3 * str.size() / 2);  // Each 2 bytes are replaced with 3 bytes.
	for(auto _ : state) {
		benchmark::DoNotOptimize(sanitize_string(str, storage));
	}
}
BENCHMARK(BM_sinsp_sanitize_string_slow_path_c1_controls_long_noalloc);

// Slow path for long string with a single, invalid byte in the middle. Triggers second pass but
// only a single replacement takes place. Storage needs allocation.
static void BM_sinsp_sanitize_string_slow_path_sparse_invalid_long_alloc(benchmark::State& state) {
	std::string str(1024, 'a');
	str[512] = '\x80';
	for(auto _ : state) {
		std::string storage;
		benchmark::DoNotOptimize(sanitize_string(str, storage));
	}
}
BENCHMARK(BM_sinsp_sanitize_string_slow_path_sparse_invalid_long_alloc);

// Slow path for long string with a single, invalid byte in the middle. Triggers second pass but
// only a single replacement takes place. Storage has enough capacity.
static void BM_sinsp_sanitize_string_slow_path_sparse_invalid_long_noalloc(
        benchmark::State& state) {
	std::string str(1024, 'a');
	str[512] = '\x80';
	std::string storage;
	storage.reserve(str.size() + 2);  // +2 accounts for 1 byte replaced by 3.
	for(auto _ : state) {
		benchmark::DoNotOptimize(sanitize_string(str, storage));
	}
}
BENCHMARK(BM_sinsp_sanitize_string_slow_path_sparse_invalid_long_noalloc);

// Slow path for long string with all bytes invalid. Worst scenario for replacement logic. Storage
// needs allocation.
static void BM_sinsp_sanitize_string_slow_path_all_invalid_long_alloc(benchmark::State& state) {
	const std::string str(1024, '\x80');
	for(auto _ : state) {
		std::string storage;
		benchmark::DoNotOptimize(sanitize_string(str, storage));
	}
}
BENCHMARK(BM_sinsp_sanitize_string_slow_path_all_invalid_long_alloc);

// Slow path for long string with all bytes invalid. Worst scenario for replacement logic. Storage
// has enough capacity.
static void BM_sinsp_sanitize_string_slow_path_all_invalid_long_noalloc(benchmark::State& state) {
	const std::string str(1024, '\x80');
	std::string storage;
	storage.reserve(str.size() * 3);  // Each byte needs 3 replacement bytes.
	for(auto _ : state) {
		benchmark::DoNotOptimize(sanitize_string(str, storage));
	}
}
BENCHMARK(BM_sinsp_sanitize_string_slow_path_all_invalid_long_noalloc);

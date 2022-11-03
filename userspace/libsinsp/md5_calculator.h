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
//
// MD5 calculator utility
//

#pragma once

#ifdef HAS_CAPTURE
#ifndef WIN32

#define HASHING_CHUNK_SIZE 32 * 1024 * 1024
#define HASHING_MAX_EXE_SIZE 300 * 1024 * 1024
#define HASHING_MAX_HASHING_TIME_NS 3LL * 1000000000
#define HASHING_USE_CACHE

class md5_cache_entry
{
public:
	string m_checksum;
	int64_t m_res;
	chrono::time_point<chrono::system_clock> m_ts;
};

class md5_calculator
{
public:
	int64_t checksum_executable(sinsp_threadinfo* tinfo, OUT string* exepath, OUT string* checksum);

private:
	int64_t checksum_file(string filename, OUT string* hash);
	void add_to_cache(string* cache_key, string* checksum, int64_t res);
	int64_t checksum_exepath(sinsp_threadinfo* tinfo, string exepath, OUT string* checksum);

	unordered_map<string, md5_cache_entry> m_cache;
};

#endif // WIN32
#endif // HAS_CAPTURE

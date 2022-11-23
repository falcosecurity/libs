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

#define HASHING_CHUNK_SIZE 32 * 1024 * 1024
#define HASHING_MAX_EXE_SIZE 300 * 1024 * 1024
#define HASHING_MAX_HASHING_TIME_NS 5LL * 1000000000
#undef HASHING_USE_CACHE

class hash_cache_entry
{
public:
	string m_checksum;
	int64_t m_res;
	chrono::time_point<chrono::system_clock> m_ts;
};

//
// This is the class that performs the checksum calculation.
// It includes a cache to avoid repeated calculation of files that have already
// been processed.
//
class file_hash_calculator
{
public:
	enum hash_type
	{
		HT_NONE,
		HT_MD5,
		HT_SHA256
	};

	int64_t checksum_process_file(sinsp_threadinfo* tinfo, string exepath, hash_type type, bool dont_cache, OUT string* checksum);
	int64_t checksum_executable(sinsp_threadinfo* tinfo, OUT string* exepath, hash_type type, OUT string* checksum);

private:
	int64_t checksum_file(string filename, hash_type type, OUT string* hash);
	void add_to_cache(string* cache_key, string* checksum, int64_t res);

	unordered_map<string, hash_cache_entry> m_cache;
};

//
// This is the table that maps MD5 hashes to malware info.
//
class checksum_table
{
public:
	checksum_table(sinsp* inspector);
	void load_files();
	bool get(string filename, OUT string* category);

private:
	void add_from_file(string filename);

	sinsp* m_inspector = NULL;
	unordered_map<string, string> m_table;
	bool m_loaded = false;
};

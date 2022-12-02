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
// NOTE: this uses mmap and will only work on Linux
//

#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fstream>
#include <openssl/md5.h>
#include <openssl/sha.h>

#include "sinsp.h"
#include "file_hash_calculator.h"

#define MAX_DIGEST_LEN (max(SHA256_DIGEST_LENGTH, MD5_DIGEST_LENGTH))

///////////////////////////////////////////////////////////////////////////////
// file_hash_calculator implementation
///////////////////////////////////////////////////////////////////////////////
int64_t file_hash_calculator::checksum_file(string filename, hash_type type, OUT string* hash)
{
#if (not defined HAS_CAPTURE) or defined WIN32
	throw sinsp_exception("file checksum not implemented on this platform");
#else // (not defined HAS_CAPTURE) or defined WIN32
	uint64_t size;
	struct stat s;
	MD5_CTX cmd5;
	SHA256_CTX csha;
	unsigned char digest[MAX_DIGEST_LEN];

	int fd = open(filename.c_str(), O_RDONLY);
	if(fd == -1)
	{
		return -errno;
	}

	//
	// Get the size of the file
	//
	int fsres = fstat (fd, & s);
	if(fsres == -1)
	{
		close(fd);
		return -errno;
	}
	size = s.st_size;

	if(size > HASHING_MAX_EXE_SIZE)
	{
		close(fd);
		return -EFBIG;
	}

	//
	// Map the file into memory. Memory mapping the file instead of reading it
	// has multiple benefits:
	// - it minimizes stack memory usage and avoids memory allocations
	// - it makes the hashing code simpler
	// - it allows to generate less system calls, and therefore pollute less the
	//   activity of the system
	//
	uint8_t* filebuf = (uint8_t*) mmap(0, size, PROT_READ, MAP_PRIVATE, fd, 0);

	//
	// Do the hashing, using openssl
	//
	(type == HT_SHA256) ? SHA256_Init(&csha) : MD5_Init(&cmd5);


//	MD5_Update(&mdContext, filebuf, size);

	uint64_t pos = 0;
	auto tstart = std::chrono::high_resolution_clock::now();
	for(pos = 0; pos + HASHING_CHUNK_SIZE < size; pos += HASHING_CHUNK_SIZE)
	{
		(type == HT_SHA256) ? SHA256_Update(&csha, filebuf + pos, HASHING_CHUNK_SIZE) :
			MD5_Update(&cmd5, filebuf + pos, HASHING_CHUNK_SIZE);

		auto tcur = std::chrono::high_resolution_clock::now();
		auto td = (tcur - tstart).count();
		if(td > HASHING_MAX_HASHING_TIME_NS)
		{
			close(fd);
			return -ETIME;
		}
	}

	(type == HT_SHA256) ? SHA256_Update(&csha, filebuf + pos, size - pos) :
		MD5_Update(&cmd5, filebuf + pos, size - pos);

	(type == HT_SHA256) ? SHA256_Final(digest, &csha) : MD5_Final(digest, &cmd5);

	close(fd);

	//
	// Convert the binary hash into a human-readable MD5 string
	//
	char tmps[3];
	tmps[2]	= 0;
	uint32_t digest_len = (type == HT_SHA256) ? SHA256_DIGEST_LENGTH : MD5_DIGEST_LENGTH;
	for(uint32_t j = 0; j < digest_len; j++)
	{
		sprintf(tmps, "%02x", digest[j]);
		(*hash) += tmps;
	}

	return 0;
#endif // (not defined HAS_CAPTURE) or defined WIN32
}

int64_t file_hash_calculator::checksum_executable(sinsp_threadinfo* tinfo,
											OUT string* exepath,
											hash_type type,
											OUT string* checksum)
{
	*exepath = tinfo->m_exepath;

#ifdef HASHING_HASH_SCRIPTS
	string comm = tinfo->m_comm;
	if(sinsp_utils::is_intepreter(comm) ||
		comm == "sh" ||
		comm == "bash" ||
		comm == "zsh" ||
		comm == "csh" ||
		comm == "tcsh")
	{
		if(tinfo->m_args.size() > 0)
		{
			char fullpath[SCAP_MAX_PATH_SIZE];
			string tcwd = tinfo->get_cwd();
			string a0 = tinfo->m_args[0];

			sinsp_utils::concatenate_paths(fullpath, SCAP_MAX_PATH_SIZE,
										   tcwd.c_str(),
										   tcwd.size(),
										   a0.c_str(),
										   a0.size(),
										   false);
			*exepath = fullpath;
		}
	}
#endif // HASHING_HASH_SCRIPTS

	return checksum_process_file(tinfo, *exepath, type, false, checksum);
}

void file_hash_calculator::add_to_cache(string* cache_key, string* checksum, int64_t res)
{
	//
	// Cache full?
	// If yes, remove the oldest entry
	//
	if(m_cache.size() >= MAX_CHECKSUM_CACHE_ENTRIES)
	{
		unordered_map<string, hash_cache_entry>::iterator oldest_it = m_cache.begin();
		for(auto it = m_cache.begin(); it != m_cache.end(); ++it)
		{
			if(it->second.m_ts < oldest_it->second.m_ts)
			{
				oldest_it = it;
			}
		}

		m_cache.erase(oldest_it);
	}

	//
	// Add the cache entry
	//
	hash_cache_entry ce;
	ce.m_checksum = *checksum;
	ce.m_res = res;
	ce.m_ts =  std::chrono::system_clock::now();
	m_cache[*cache_key] = ce;
}

int64_t file_hash_calculator::checksum_process_file(sinsp_threadinfo* tinfo,
													string exepath,
													hash_type type,
													bool dont_cache,
													OUT string* checksum)
{
	//
	// We use /proc/<pid>/root to navigate into the process file system and read the
	// executable. This works for containers as well since, for a container,
	// /proc/<pid>/root lets us access the container FS.
	// An even simpler way to access the executable would be /proc/<pid>/exe. We
	// don't use it because it has the disadvantage of not allowing ancestor list
	// navigation (see below). Also, it doesn't work for intepreted scripts.
	// Based on my benchmarks, BTW, using exe doesn't offer any performance
	// advantage.
	//
	string fexepath = "/proc/" + to_string(tinfo->m_pid) + "/root" + exepath;
	string cache_key = tinfo->m_container_id + exepath;

	//
	// Do we have this executable in the cache? If yes, just return the cache entry.
	//
#ifdef HASHING_USE_CACHE
	auto it = m_cache.find(cache_key);
	if(it != m_cache.end())
	{
		*checksum = it->second.m_checksum;
		// Refresh the cache entry timestamp
		it->second.m_ts = std::chrono::system_clock::now();
		return it->second.m_res;
	}
#endif

	int64_t res = checksum_file(fexepath, type, checksum);

	//
	// If the file doesn't exist, it means that the process has already exited.
	// In such situation we try to navigate the ancestor list, looking for
	// a process still alive in the container that we can use to access the
	// file.
	//
	if(res == -ENOENT)
	{
		sinsp_threadinfo* ptinfo = tinfo->get_parent_thread();
		if(ptinfo == NULL)
		{
			*checksum = "";
			return -ECHILD;
		}

		if(ptinfo->m_container_id != ptinfo->m_container_id)
		{
			*checksum = "";
			return -ENODEV;
		}

		return checksum_process_file(ptinfo, exepath, type, dont_cache, checksum);
	}

	//
	// Succcess.
	// Add the executable to the cache
	//
	if(!dont_cache)
	{
		add_to_cache(&cache_key, checksum, res);
	}

	return res;
}

///////////////////////////////////////////////////////////////////////////////
// checksum_table implementation
///////////////////////////////////////////////////////////////////////////////
checksum_table::checksum_table(sinsp* inspector)
{
	m_inspector = inspector;
}

void checksum_table::add_from_file(string filename)
{
	FILE* f = fopen(filename.c_str(), "r");
	if(f == NULL)
	{
		ASSERT(false); // The existence of the file should have been validated before
		throw sinsp_exception("can't open signatures file " + filename);
	}

	char line[1024];
	while(fgets(line, sizeof(line), f) != NULL)
	{
		// skip comments
		if(line[0] == '#')
		{
			continue;
		}

		string sline(line);
		trim(sline);

		// split the line into fields
		vector<string> fields = sinsp_split(string(sline), ',');

		// Check that the line is well formed
		if(fields.size() != 2)
		{
			fclose(f);
			throw sinsp_exception("malformed line in signatures file " + filename + ": " + sline);
		}

		string hash = fields[0];
		trim(hash);
		string category = fields[1];
		trim(category);


		if(hash.size() != 64 || category.empty())
		{
			fclose(f);
			throw sinsp_exception("invalid line in signatures file " + filename + ": " + sline);
		}

		m_table[hash] = category;
	}

	fclose(f);
}

void checksum_table::load_files()
{
	for(auto f : m_inspector->m_exec_hashing_checksum_files)
	{
		add_from_file(f);
	}

	m_loaded = true;
}

bool checksum_table::get(string filename, OUT string* category)
{
	if(!m_loaded)
	{
		load_files();
	}

	auto it = m_table.find(filename);
	if(it == m_table.end())
	{
		return false;
	}

	*category = it->second;
	return true;
}

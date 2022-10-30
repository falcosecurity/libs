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

#ifdef HAS_CAPTURE
#ifndef WIN32

#include <stdio.h>
#include <fcntl.h>
#include <openssl/md5.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "sinsp.h"
#include "md5_calculator.h"

#define IO_BUF_SIZE = 65536;

int64_t md5_calculator::hash_file(string filename, OUT string* hash)
{
	uint64_t size;
	struct stat s;
	MD5_CTX mdContext;
	unsigned char digest[MD5_DIGEST_LENGTH];

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

	//
	// Map the file into memory. Memory mapping the file instead of reading it
	// has multiple benefits:
	// - it minimizes stack memory usage or allocations
	// - it makes the hashing code simpler
	// - it allows to generate less system calls, and therefore pollute less the
	//   activity of the system
	//
	uint8_t* filebuf = (uint8_t*) mmap(0, size, PROT_READ, MAP_PRIVATE, fd, 0);

	//
	// Do the hashing using openssl
	//
	MD5_Init(&mdContext);
	MD5_Update(&mdContext, filebuf, size);
	MD5_Final(digest, &mdContext);

	close(fd);

	//
	// Convert the binary hash into a human-readable MD5 string
	//
	char tmps[3];
	tmps[2]	= 0;
	for(auto j = 0; j < MD5_DIGEST_LENGTH; j++)
	{
		sprintf(tmps, "%02x", digest[j]);
		(*hash) += tmps;
	}

	return 0;
}

int64_t md5_calculator::hash_proc_executable(sinsp_threadinfo* tinfo, OUT string* hash)
{
	string fexepath = "/proc/" + to_string(tinfo->m_pid) + "/root" + tinfo->m_exepath;
	int64_t res = hash_file(fexepath, hash);

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
			*hash = "";
			return -ECHILD;
		}

		if(ptinfo->m_container_id != ptinfo->m_container_id)
		{
			*hash = "";
			return -ENODEV;
		}

		return hash_proc_executable(ptinfo, OUT hash);
	}

	return res;
}

#endif // WIN32
#endif // HAS_CAPTURE

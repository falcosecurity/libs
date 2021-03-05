/*
Copyright (C) 2013-2018 Draios Inc dba Sysdig.

This file is part of sysdig.

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

#ifndef _WIN32
#include <unistd.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/time.h>
#ifdef __GLIBC__
#include <execinfo.h>
#endif
#include <unistd.h>
#include <sys/time.h>
#include <netdb.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <fnmatch.h>
#include <string>
#else
#pragma comment(lib, "Ws2_32.lib")
#include <WinSock2.h>
#include "Shlwapi.h"
#pragma comment(lib, "shlwapi.lib")
#endif
#include <algorithm>
#include <functional>
#include <errno.h>

#include "sinsp.h"
#include "sinsp_int.h"
#include "sinsp_errno.h"
#include "sinsp_signal.h"
#include "filter.h"
#include "filterchecks.h"
#include "utils.h"
#include "chisel.h"
#include "chisel_utils.h"
#include "protodecoder.h"
#include "uri.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

const chiseldir_info g_chisel_dirs_array[] =
	{
		{false, ""}, // file as is
#ifdef _WIN32
		{false, "c:/sysdig/chisels/"},
#endif
		{false, "./chisels/"},
		{true, "~/.chisels/"},
};

vector<chiseldir_info>* g_chisel_dirs = NULL;

#ifndef _WIN32
static std::string realpath_ex(const std::string& path)
{
	char *home;
	char* resolved;

	if(!path.empty() && path[0]=='~' && (home = getenv("HOME")))
	{
		std::string expanded_home = home;
		expanded_home += path.c_str()+1;
		resolved = realpath(expanded_home.c_str(), nullptr);
	}
	else
	{
		resolved = realpath(path.c_str(), nullptr);
	}

	if (!resolved)
	{
		return "";
	}
	std::string ret = resolved;
	free(resolved);
	return resolved;
}
#endif

//
// loading time initializations
//
chisel_initializer::chisel_initializer()
{
	//
	// Init the chisel directory list
	//
	g_chisel_dirs = NULL;
	g_chisel_dirs = new vector<chiseldir_info>();

	for(uint32_t j = 0; j < sizeof(g_chisel_dirs_array) / sizeof(g_chisel_dirs_array[0]); j++)
	{
		if(g_chisel_dirs_array[j].m_need_to_resolve)
		{
#ifndef _WIN32
			std::string resolved_path = realpath_ex(g_chisel_dirs_array[j].m_dir);
			if(!resolved_path.empty())
			{
				if(resolved_path[resolved_path.size() - 1] != '/')
				{
					resolved_path += '/';
				}

				chiseldir_info cdi;
				cdi.m_need_to_resolve = false;
				cdi.m_dir = std::move(resolved_path);
				g_chisel_dirs->push_back(cdi);
			}
#else
			g_chisel_dirs->push_back(g_chisel_dirs_array[j]);
#endif
		}
		else
		{
			g_chisel_dirs->push_back(g_chisel_dirs_array[j]);
		}
	}
}

chisel_initializer::~chisel_initializer()
{
	if(g_chisel_dirs)
	{
		delete g_chisel_dirs;
	}
}

void chisel_add_dir(string dirname, bool front_add)
{
	trim(dirname);

	if(dirname[dirname.size() -1] != '/')
	{
		dirname += "/";
	}

	chiseldir_info ncdi;

	ncdi.m_dir = std::move(dirname);
	ncdi.m_need_to_resolve = false;

	if(front_add)
	{
		g_chisel_dirs->insert(g_chisel_dirs->begin(), ncdi);
	}
	else
	{
		g_chisel_dirs->push_back(ncdi);
	}
}
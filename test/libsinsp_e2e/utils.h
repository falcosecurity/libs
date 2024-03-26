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

#pragma once

#include <sstream>
#include <string>
#include <vector>

#include <gtest/gtest.h>

inline bool parse_tuple(const std::string& tuple,
						std::string& src_addr,
						std::string& src_port,
						std::string& dst_addr,
						std::string& dst_port)
{
	std::string token;
	std::stringstream ss(tuple);
	std::vector<std::string> tst;
	std::string srcstr;
	std::string dststr;

	if(tuple.find("->") == std::string::npos)
	{
		return false;
	}

	while (std::getline(ss, token, '>')) {
		tst.push_back(token);
	}

	srcstr = tst[0].substr(0, tst[0].size() - 1);
	dststr = tst[1];

	ss.clear();
	ss.str(srcstr);
	std::vector<std::string> sst;
	while (std::getline(ss, token, ':')) {
		sst.push_back(token);
	}

	EXPECT_EQ(2, (int)sst.size());
	src_addr = sst[0];
	src_port = sst[1];

	ss.clear();
	ss.str(dststr);
	std::vector<std::string> dst;
	while (std::getline(ss, token, ':')) {
		dst.push_back(token);
	}
	EXPECT_EQ(2, (int)dst.size());
	dst_addr = dst[0];
	dst_port = dst[1];

	return true;
}

class nsenter
{
public:
	nsenter(int pid, const std::string& type);
	virtual ~nsenter();

private:
	int open_ns_fd(int pid, const std::string& type);
	static std::unordered_map<std::string, int> m_home_ns;
	std::string m_type;
};

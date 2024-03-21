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

#include <libsinsp/sinsp.h>
#include <libsinsp/sinsp_int.h>
#include <libsinsp/threadinfo.h>

#include <gtest/gtest.h>
#include <string>
#include <vector>

class threadinfo_test : public testing::Test
{
};

static void check_iov(struct iovec* iov,
                      int iovcnt,
                      std::string rem,
                      std::vector<struct iovec>& expected,
                      std::string expectedrem)
{
	ASSERT_EQ((unsigned)iovcnt, expected.size());

	for (int i = 0; i < iovcnt; i++)
	{
		ASSERT_EQ(iov[i].iov_len, expected[i].iov_len);
		ASSERT_TRUE(memcmp(iov[i].iov_base, expected[i].iov_base, iov[i].iov_len) == 0);
	}

	EXPECT_TRUE(rem == expectedrem);
}

enum test_type
{
	TEST_ARGS = 0,
	TEST_ENV = 1,
	TEST_CGROUPS = 2
};

static void run_test(test_type ttype,
                     std::vector<std::string>& vals,
                     std::vector<std::string>& expected,
                     std::string expectedrem)
{
	sinsp_threadinfo ti(nullptr);
	struct iovec* iov;
	int iovcnt;
	std::string rem;
	sinsp_threadinfo::cgroups_t cg;

	for (auto& val : vals)
	{
		switch (ttype)
		{
		case TEST_ARGS:
			ti.m_args.push_back(val.c_str());
			break;
		case TEST_ENV:
			ti.m_env.push_back(val.c_str());
			break;
		case TEST_CGROUPS:
			size_t pos = val.find("=");
			ASSERT_NE(pos, std::string::npos);
			ti.cgroups().push_back(make_pair(val.substr(0, pos), val.substr(pos + 1)));
			break;
		}
	}

	switch (ttype)
	{
	case TEST_ARGS:
		ti.args_to_iovec(&iov, &iovcnt, rem);
		break;
	case TEST_ENV:
		ti.env_to_iovec(&iov, &iovcnt, rem);
		break;
	case TEST_CGROUPS:
		cg = ti.cgroups();
		ti.cgroups_to_iovec(&iov, &iovcnt, rem, cg);
		break;
	};

	std::vector<struct iovec> expected_iov;
	for (auto& exp : expected)
	{
		if (ttype == TEST_ARGS || ttype == TEST_ENV)
		{
			// A trailing NULL is assumed for all values
			expected_iov.emplace_back(iovec{(void*)exp.c_str(), exp.size() + 1});
		}
		else
		{
			expected_iov.emplace_back(iovec{(void*)exp.data(), exp.size()});
		}
	}

	check_iov(iov, iovcnt, rem, expected_iov, expectedrem);

	free(iov);
}

TEST_F(threadinfo_test, args)
{
	std::vector<std::string> args = {"-i", "206", "--switch", "f"};
	std::string expectedrem;

	run_test(TEST_ARGS, args, args, expectedrem);
}

TEST_F(threadinfo_test, args_skip)
{
	std::string full(SCAP_MAX_ARGS_SIZE - 1, 'a');

	std::vector<std::string> args = {full, "will-be-skipped"};
	std::vector<std::string> expected = {full};
	std::string expectedrem;

	run_test(TEST_ARGS, args, expected, expectedrem);
}

TEST_F(threadinfo_test, argstrunc_single)
{
	std::string full(SCAP_MAX_ARGS_SIZE, 'a');
	std::string trunc(SCAP_MAX_ARGS_SIZE - 1, 'a');

	std::vector<std::string> args = {full, "will-be-skipped"};
	std::vector<std::string> expected = {trunc};
	std::string expectedrem = trunc;

	run_test(TEST_ARGS, args, expected, expectedrem);
}

TEST_F(threadinfo_test, argstrunc_multi)
{
	std::string full(SCAP_MAX_ARGS_SIZE, 'a');
	std::string trunc(SCAP_MAX_ARGS_SIZE - 6, 'a');

	std::vector<std::string> args = {"0123", full};
	std::vector<std::string> expected = {"0123", trunc};
	std::string expectedrem = trunc;

	run_test(TEST_ARGS, args, expected, expectedrem);
}

TEST_F(threadinfo_test, envs)
{
	std::vector<std::string> envs = {"-i", "206", "--switch", "f"};
	std::string expectedrem;

	run_test(TEST_ENV, envs, envs, expectedrem);
}

TEST_F(threadinfo_test, envs_skip)
{
	std::string full(SCAP_MAX_ENV_SIZE - 1, 'a');

	std::vector<std::string> envs = {full, "will-be-skipped"};
	std::vector<std::string> expected = {full};
	std::string expectedrem;

	run_test(TEST_ENV, envs, expected, expectedrem);
}

TEST_F(threadinfo_test, envstrunc_single)
{
	std::string full(SCAP_MAX_ENV_SIZE, 'a');
	std::string trunc(SCAP_MAX_ENV_SIZE - 1, 'a');

	std::vector<std::string> envs = {full, "will-be-skipped"};
	std::vector<std::string> expected = {trunc};
	std::string expectedrem = trunc;

	run_test(TEST_ENV, envs, expected, expectedrem);
}

TEST_F(threadinfo_test, envstrunc_multi)
{
	std::string full(SCAP_MAX_ENV_SIZE, 'a');
	std::string trunc(SCAP_MAX_ENV_SIZE - 6, 'a');

	std::vector<std::string> envs = {"0123", full};
	std::vector<std::string> expected = {"0123", trunc};
	std::string expectedrem = trunc;

	run_test(TEST_ENV, envs, expected, expectedrem);
}

TEST_F(threadinfo_test, cgroups)
{
	std::vector<std::string> cgroups = {
	    "cpuset=/docker/875f9d8728e84761e4669b21acbf035b3a3fda62d7f6e35dd857781932cd74e8",
	    "perf_event=/docker/875f9d8728e84761e4669b21acbf035b3a3fda62d7f6e35dd857781932cd74e8",
	    "memory=/docker/875f9d8728e84761e4669b21acbf035b3a3fda62d7f6e35dd857781932cd74e8",
	    "rdma=/"};

	std::vector<std::string> expected = {
	    "cpuset",
	    "=",
	    "/docker/875f9d8728e84761e4669b21acbf035b3a3fda62d7f6e35dd857781932cd74e8",
	    "perf_event",
	    "=",
	    "/docker/875f9d8728e84761e4669b21acbf035b3a3fda62d7f6e35dd857781932cd74e8",
	    "memory",
	    "=",
	    "/docker/875f9d8728e84761e4669b21acbf035b3a3fda62d7f6e35dd857781932cd74e8",
	    "rdma",
	    "=",
	    "/"};

	expected[2].push_back('\0');
	expected[5].push_back('\0');
	expected[8].push_back('\0');
	expected[11].push_back('\0');
	std::string expectedrem;

	run_test(TEST_CGROUPS, cgroups, expected, expectedrem);
}

TEST_F(threadinfo_test, cgroups_skip)
{
	std::string full(SCAP_MAX_CGROUPS_SIZE - 8, 'a');

	std::vector<std::string> cgroups = {"cpuset=" + full, "rdma=will-be-skipped"};
	std::vector<std::string> expected = {"cpuset", "=", full};
	expected[2].push_back('\0');
	std::string expectedrem;

	run_test(TEST_CGROUPS, cgroups, expected, expectedrem);
}

TEST_F(threadinfo_test, cgroupstrunc_single)
{
	std::string full(SCAP_MAX_CGROUPS_SIZE - 7, 'a');
	std::string trunc(SCAP_MAX_CGROUPS_SIZE - 8, 'a');

	std::vector<std::string> cgroups = {"cpuset=" + full, "rdma=will-be-skipped"};
	std::vector<std::string> expected = {"cpuset", "=", trunc};
	expected[2].push_back('\0');
	std::string expectedrem = trunc;

	run_test(TEST_CGROUPS, cgroups, expected, expectedrem);
}

TEST_F(threadinfo_test, cgroupstrunc_multi)
{
	std::string full(SCAP_MAX_CGROUPS_SIZE, 'a');
	std::string trunc(SCAP_MAX_CGROUPS_SIZE - 15, 'a');

	std::vector<std::string> cgroups = {"cpuset=1", "rdma=" + full};
	std::vector<std::string> expected = {"cpuset", "=", "1", "rdma", "=", trunc};
	expected[2].push_back('\0');
	expected[5].push_back('\0');
	std::string expectedrem = trunc;

	run_test(TEST_CGROUPS, cgroups, expected, expectedrem);
}

TEST_F(threadinfo_test, cgroupstrunc_noeq)
{
	std::string full(SCAP_MAX_CGROUPS_SIZE, 'a');
	std::string trunc(SCAP_MAX_CGROUPS_SIZE - 10, 'a');

	std::vector<std::string> cgroups = {"cpuset=1", full + "=" + "1"};
	std::vector<std::string> expected = {"cpuset", "=", "1", trunc};
	expected[2].push_back('\0');
	expected[3].push_back('\0');
	std::string expectedrem = trunc;

	run_test(TEST_CGROUPS, cgroups, expected, expectedrem);
}
